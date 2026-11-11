package core_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-meta/pkg/messagix/httpclient"
	"go.mau.fi/mautrix-meta/pkg/messagix/loginerrors"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/mediaproxy"

	"github.com/tzarebczan/eggomi-meta-bridge/config"
	"github.com/tzarebczan/eggomi-meta-bridge/core"
	"github.com/tzarebczan/eggomi-meta-bridge/link"
	"github.com/tzarebczan/eggomi-meta-bridge/seal"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/fakenet"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/harness"
)

type vectors struct {
	KK struct {
		KeeperStatic string `json:"keeperStatic"`
		KeeperPublic string `json:"keeperPublic"`
		BridgeStatic string `json:"bridgeStatic"`
		BridgePublic string `json:"bridgePublic"`
	} `json:"kk"`
	Seal struct {
		SealerPublic string            `json:"sealerPublic"`
		Blob         json.RawMessage   `json:"blob"`
		Plaintext    map[string]string `json:"plaintext"`
		Variants     struct {
			Fresh           []json.RawMessage `json:"fresh"`
			OtherInstance   json.RawMessage   `json:"otherInstance"`
			OtherGeneration json.RawMessage   `json:"otherGeneration"`
			OtherOrigin     json.RawMessage   `json:"otherOrigin"`
			OtherField      json.RawMessage   `json:"otherField"`
			OtherAudience   json.RawMessage   `json:"otherAudience"`
			ExtraCookie     json.RawMessage   `json:"extraCookie"`
			MissingXs       json.RawMessage   `json:"missingXs"`
		} `json:"variants"`
	} `json:"seal"`
}

var canaries = []string{"CANARY-DATR-VALUE", "CANARY-SB-VALUE", "CANARY-XS-VALUE", "CANARY-EXTRA-VALUE"}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("../testdata/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type rig struct {
	t      *testing.T
	v      vectors
	env    *harness.Env
	net    *fakenet.Network
	addr   string
	logs   *syncBuffer
	frames *syncBuffer // every answer the keeper side received

	mu        sync.Mutex
	loginErr  error
	loginSeen []map[string]any
	download  func(ctx context.Context, id networkid.MediaID) (mediaproxy.GetMediaResponse, error)
	downloads int
}

type rigOpt func(*core.Options)

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	r := &rig{t: t, v: loadVectors(t), net: fakenet.New(), logs: &syncBuffer{}, frames: &syncBuffer{}}
	log := zerolog.New(r.logs).Level(zerolog.TraceLevel)
	env, err := harness.Start(t.TempDir(), r.net, log)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	r.env = env
	t.Cleanup(func() { env.Stop(context.Background()) })
	o := core.Options{
		Bridge: env.Bridge, Sink: env.Sink, Out: env.Out, Ops: env.Ops, Media: env.Media, DB: env.DB,
		Login: r.fakeLogin,
		LoginID: func(creds map[string]any) networkid.UserLoginID {
			s, _ := creds["c_user"].(string)
			return networkid.UserLoginID(s)
		},
		Download: func(ctx context.Context, id networkid.MediaID, _ map[string]string) (mediaproxy.GetMediaResponse, error) {
			r.mu.Lock()
			r.downloads++
			dl := r.download
			r.mu.Unlock()
			if dl == nil {
				return nil, errors.New("no media")
			}
			return dl(ctx, id)
		},
		MaxMedia: config.MaxMediaBytes,
		Seal: core.SealConfig{
			BridgePrivate: unhex(t, r.v.KK.BridgeStatic),
			SealerPublic:  unhex(t, r.v.Seal.SealerPublic),
			Audience:      r.v.KK.KeeperPublic,
			Instance:      "meta-bridge",
			Generation:    1,
		},
		Log: log, Version: "test", Upstream: "da5fbd43",
		OlderSpacing: 150 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(&o)
	}
	c, err := core.New(o)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	srv := &link.Server{StaticPrivate: unhex(t, r.v.KK.BridgeStatic), KeeperPublic: unhex(t, r.v.KK.KeeperPublic), Handler: c, Log: log}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	r.addr = ln.Addr().String()
	return r
}

func (r *rig) fakeLogin(ctx context.Context, user *bridgev2.User, creds map[string]any) error {
	r.mu.Lock()
	cp := map[string]any{}
	for k, v := range creds {
		cp[k] = v
	}
	r.loginSeen = append(r.loginSeen, cp)
	err := r.loginErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	id, _ := creds["c_user"].(string)
	_, err = user.NewLogin(ctx, &database.UserLogin{ID: networkid.UserLoginID(id), RemoteName: "Canary Owner"}, nil)
	return err
}

func (r *rig) dial() *link.Client {
	r.t.Helper()
	c, err := link.Dial(r.addr, unhex(r.t, r.v.KK.KeeperStatic), unhex(r.t, r.v.KK.BridgePublic))
	if err != nil {
		r.t.Fatalf("dial: %v", err)
	}
	r.t.Cleanup(func() { c.Close() })
	return c
}

// call returns the result object or the error code.
func (r *rig) call(c *link.Client, method string, params any) (map[string]any, string) {
	r.t.Helper()
	var res map[string]any
	err := c.Call(method, params, &res)
	frame, _ := json.Marshal(res)
	r.frames.Write(frame)
	var re *link.RemoteError
	if errors.As(err, &re) {
		r.frames.Write([]byte(re.Code))
		return nil, re.Code
	} else if err != nil {
		r.t.Fatalf("%s: %v", method, err)
	}
	return res, ""
}

func (r *rig) mustCall(c *link.Client, method string, params any) map[string]any {
	r.t.Helper()
	res, code := r.call(c, method, params)
	if code != "" {
		r.t.Fatalf("%s: code %s", method, code)
	}
	return res
}

func (r *rig) wantCode(c *link.Client, method string, params any, want string) {
	r.t.Helper()
	if _, code := r.call(c, method, params); code != want {
		r.t.Fatalf("%s: want %s, got %q", method, want, code)
	}
}

func (r *rig) noCanaries() {
	r.t.Helper()
	for _, where := range []struct{ name, text string }{{"logs", r.logs.String()}, {"frames", r.frames.String()}} {
		for _, c := range canaries {
			if strings.Contains(where.text, c) {
				r.t.Fatalf("canary %s found in %s", c, where.name)
			}
		}
	}
}

type evt struct {
	Seq     int64          `json:"seq"`
	Kind    string         `json:"kind"`
	Portal  string         `json:"portal"`
	Data    map[string]any `json:"data"`
	Size    int            `json:"size"`
	Chunked bool           `json:"chunked"`
}

func events(t *testing.T, res map[string]any) []evt {
	t.Helper()
	raw, _ := json.Marshal(res["events"])
	var out []evt
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// drain long-polls from after until pred matches an event; returns it.
func (r *rig) waitEvent(c *link.Client, after int64, pred func(evt) bool) evt {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res := r.mustCall(c, "events.next", map[string]any{"after": after, "waitMs": 1000})
		for _, e := range events(r.t, res) {
			if pred(e) {
				return e
			}
			after = e.Seq
		}
	}
	r.t.Fatalf("event never arrived")
	return evt{}
}

const thread = networkid.PortalID("thread-1")

func ghostMsg(portal networkid.PortalID, msgID networkid.MessageID, text string, ts time.Time) *simplevent.PreConvertedMessage {
	return &simplevent.PreConvertedMessage{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventMessage,
			PortalKey:    networkid.PortalKey{ID: portal, Receiver: fakenet.LoginID},
			CreatePortal: true,
			Sender:       bridgev2.EventSender{Sender: "ghost-1"},
			Timestamp:    ts,
		},
		ID: msgID,
		Data: &bridgev2.ConvertedMessage{Parts: []*bridgev2.ConvertedMessagePart{{
			Type:    event.EventMessage,
			Content: &event.MessageEventContent{MsgType: event.MsgText, Body: text},
		}}},
	}
}

func (r *rig) loginFake() *bridgev2.UserLogin {
	r.t.Helper()
	ul, err := r.env.Login(context.Background(), fakenet.LoginID, "Owner")
	if err != nil {
		r.t.Fatalf("login: %v", err)
	}
	return ul
}

func TestStatusAndEventStream(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	st := r.mustCall(c, "status", map[string]any{})
	if epoch, _ := st["epoch"].(string); len(epoch) != 32 || st["login"] != nil || st["upstream"] != "da5fbd43" {
		t.Fatalf("status: %v", st)
	}
	r.wantCode(c, "status", map[string]any{"extra": 1}, "bad_request")
	r.wantCode(c, "no.such.method", map[string]any{}, "unknown_method")
	r.wantCode(c, "events.next", map[string]any{"after": 0, "waitMs": 30001}, "bad_request")
	r.wantCode(c, "events.next", map[string]any{"after": 1 << 40}, "cursor_ahead")

	ul := r.loginFake()
	latest := int64(st["latest"].(float64))
	poller := r.dial()
	got := make(chan evt, 1)
	go func() {
		got <- r.waitEvent(poller, latest, func(e evt) bool { return e.Kind == "item" && e.Data["text"] == "hello" })
	}()
	time.Sleep(200 * time.Millisecond)
	ul.QueueRemoteEvent(ghostMsg(thread, "msg-1", "hello", time.Now()))
	var item evt
	select {
	case item = <-got:
	case <-time.After(20 * time.Second):
		t.Fatal("long poll never returned the item")
	}
	if item.Portal != string(thread) || item.Data["remoteId"] != "msg-1" {
		t.Fatalf("item: %+v", item)
	}

	// An empty wait returns after waitMs with no events.
	now := r.mustCall(c, "status", map[string]any{})
	head := int64(now["latest"].(float64))
	start := time.Now()
	res := r.mustCall(c, "events.next", map[string]any{"after": head, "waitMs": 300})
	if len(events(t, res)) != 0 || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("empty wait: %v after %s", res, time.Since(start))
	}

	pendingBefore := int(now["pending"].(float64))
	r.mustCall(c, "ack", map[string]any{"seq": item.Seq})
	after := r.mustCall(c, "status", map[string]any{})
	if int(after["pending"].(float64)) >= pendingBefore {
		t.Fatalf("ack did not drop events: %v -> %v", pendingBefore, after["pending"])
	}
	for _, e := range events(t, r.mustCall(c, "events.next", map[string]any{"after": 0})) {
		if e.Seq <= item.Seq {
			t.Fatalf("acked event %d replayed", e.Seq)
		}
	}
	r.wantCode(c, "ack", map[string]any{"seq": head + 1000}, "cursor_ahead")
	r.wantCode(c, "ack", map[string]any{}, "bad_request")
}

func TestOversizeEventIsChunked(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	ul := r.loginFake()
	// 40 KB of two-byte runes plus quotes that JSON escaping doubles: the
	// encoded event is larger than one frame.
	big := strings.Repeat("é", 20000) + strings.Repeat("\"", 15000)
	ul.QueueRemoteEvent(ghostMsg(thread, "msg-big", big, time.Now()))
	ul.QueueRemoteEvent(ghostMsg(thread, "msg-after", "after", time.Now().Add(time.Second)))
	var stub evt
	after := int64(0)
	deadline := time.Now().Add(15 * time.Second)
	for stub.Seq == 0 && time.Now().Before(deadline) {
		res := r.mustCall(c, "events.next", map[string]any{"after": after, "waitMs": 500})
		for _, e := range events(t, res) {
			if e.Chunked {
				stub = e
				if res["more"] != true || len(events(t, res)) != 1 {
					t.Fatalf("a stub travels alone with more=true: %v", res)
				}
				break
			}
			after = e.Seq
		}
	}
	if stub.Seq == 0 || stub.Kind != "item" {
		t.Fatalf("no chunked stub: %+v", stub)
	}
	var whole []byte
	for len(whole) < stub.Size {
		res := r.mustCall(c, "events.chunk", map[string]any{"seq": stub.Seq, "offset": len(whole)})
		part, err := base64.StdEncoding.DecodeString(res["data"].(string))
		if err != nil || len(part) == 0 {
			t.Fatalf("chunk: %v", err)
		}
		whole = append(whole, part...)
	}
	var full evt
	if err := json.Unmarshal(whole, &full); err != nil {
		t.Fatalf("reassembled event: %v", err)
	}
	if full.Seq != stub.Seq || full.Data["text"] != big {
		t.Fatalf("reassembled event differs")
	}
	next := r.waitEvent(c, stub.Seq, func(e evt) bool { return e.Kind == "item" })
	if next.Data["text"] != "after" {
		t.Fatalf("stream did not continue after the stub: %+v", next)
	}
	r.mustCall(c, "ack", map[string]any{"seq": stub.Seq})
	r.wantCode(c, "events.chunk", map[string]any{"seq": stub.Seq, "offset": 0}, "gone")
}

func TestOutbound(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	send := func(opID, text string) map[string]any {
		return map[string]any{"opId": opID, "conversation": string(thread), "text": text}
	}
	r.wantCode(c, "send", send("op-1", "hi"), "not_logged_in")
	ul := r.loginFake()
	ul.QueueRemoteEvent(ghostMsg(thread, "msg-1", "hello", time.Now()))
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "item" })

	res := r.mustCall(c, "send", send("op-1", "hello back"))
	op := res["op"].(map[string]any)
	if res["duplicate"] != false || (op["state"] != "committed" && op["state"] != "accepted") || op["id"] != "op-1" {
		t.Fatalf("send answer: %v", res)
	}
	settled := r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "op" && e.Data["opId"] == "op-1" })
	if settled.Data["state"] != "accepted" || settled.Data["remoteId"] != "remote-op-1" {
		t.Fatalf("op settle: %v", settled.Data)
	}
	sent := len(r.net.Client.SentRecords())
	dup := r.mustCall(c, "send", send("op-1", "hello back"))
	if dup["duplicate"] != true || dup["op"].(map[string]any)["state"] != "accepted" {
		t.Fatalf("duplicate answer: %v", dup)
	}
	r.wantCode(c, "send", send("op-1", "other text"), "op_mismatch")
	if len(r.net.Client.SentRecords()) != sent {
		t.Fatalf("a repeated op id reached the network")
	}

	r.wantCode(c, "send", send("op-2", ""), "bad_request")
	r.wantCode(c, "send", send("op-2", "   "), "bad_request")
	r.wantCode(c, "send", send("op-2", strings.Repeat("x", core.MaxTextRunes+1)), "bad_request")
	r.wantCode(c, "send", send("op 2", "x"), "bad_request")
	r.wantCode(c, "send", map[string]any{"opId": "op-2", "conversation": "no-such", "text": "x"}, "unknown_conversation")
	r.wantCode(c, "send", map[string]any{"opId": "op-2", "conversation": string(thread), "text": "x", "replyTo": "no-such"}, "target_gone")
	if row := r.mustCall(c, "op", map[string]any{"opId": "op-2"}); row["op"] != nil {
		t.Fatalf("refused op was committed: %v", row)
	}
	r.mustCall(c, "send", map[string]any{"opId": "op-3", "conversation": string(thread), "text": "a reply", "replyTo": "msg-1"})

	react := func(opID string, emoji any) map[string]any {
		return map[string]any{"opId": opID, "conversation": string(thread), "item": "msg-1", "emoji": emoji}
	}
	r.mustCall(c, "react", react("op-r1", "\U0001F44D"))
	if e := r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "op" && e.Data["opId"] == "op-r1" }); e.Data["state"] != "accepted" {
		t.Fatalf("react settle: %v", e.Data)
	}
	r.mustCall(c, "react", react("op-r2", nil))
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "op" && e.Data["opId"] == "op-r2" })
	r.wantCode(c, "react", react("op-r3", "abc"), "bad_request")
	r.wantCode(c, "react", react("op-r3", ""), "bad_request")

	r.mustCall(c, "markRead", map[string]any{"conversation": string(thread), "upTo": "msg-1"})
	r.wantCode(c, "markRead", map[string]any{"conversation": string(thread), "upTo": "nope"}, "target_gone")

	rec := r.mustCall(c, "reconcile", map[string]any{"opId": "op-1"})
	if rec["op"].(map[string]any)["state"] != "accepted" {
		t.Fatalf("reconcile: %v", rec)
	}
	r.wantCode(c, "reconcile", map[string]any{"opId": "op-none"}, "unknown_op")

	kinds := map[string]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !(kinds["reaction"] && kinds["reaction_remove"] && kinds["read_receipt"]) {
		for _, s := range r.net.Client.SentRecords() {
			kinds[s.Kind] = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !kinds["reaction"] || !kinds["reaction_remove"] || !kinds["read_receipt"] {
		t.Fatalf("network calls: %v", kinds)
	}
}

func TestOlderPagesOnDemand(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	ul := r.loginFake()
	const hthread = networkid.PortalID("thread-h")
	base := time.Now().Add(-48 * time.Hour)
	var hist []*bridgev2.BackfillMessage
	for i := 0; i < 120; i++ {
		hist = append(hist, &bridgev2.BackfillMessage{
			ConvertedMessage: &bridgev2.ConvertedMessage{Parts: []*bridgev2.ConvertedMessagePart{{
				Type: event.EventMessage, Content: &event.MessageEventContent{MsgType: event.MsgText, Body: fmt.Sprintf("old %d", i)},
			}}},
			Sender:    bridgev2.EventSender{Sender: "ghost-1"},
			ID:        networkid.MessageID(fmt.Sprintf("old-%d", i)),
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	r.net.Client.SetHistory(hthread, hist)
	ul.QueueRemoteEvent(ghostMsg(hthread, "live-1", "live", time.Now()))
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "item" && e.Data["remoteId"] == "live-1" })

	r.wantCode(c, "older", map[string]any{"conversation": "no-such"}, "unknown_conversation")
	countHistory := func() int {
		n := 0
		for _, e := range events(t, r.mustCall(c, "events.next", map[string]any{"after": 0, "limit": 500})) {
			if e.Kind == "item" && e.Data["source"] == "history" {
				n++
			}
		}
		return n
	}
	pages := 0
	for {
		res, code := r.call(c, "older", map[string]any{"conversation": string(hthread)})
		if code == "busy" {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if code != "" {
			t.Fatalf("older: %s", code)
		}
		if res["queued"] == false {
			break
		}
		pages++
		want := min(pages*config.HistoryPage, len(hist))
		deadline := time.Now().Add(10 * time.Second)
		for countHistory() < want && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if got := countHistory(); got != want {
			t.Fatalf("after page %d: %d history items, want %d", pages, got, want)
		}
		if pages == 1 {
			r.wantCode(c, "older", map[string]any{"conversation": string(hthread)}, "busy")
		}
		if pages > 5 {
			t.Fatalf("older never reported the end")
		}
	}
	if pages != 3 {
		t.Fatalf("pages: %d, want 3 (50+50+20)", pages)
	}
}

func TestMediaGet(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	fetch := func(ref string) ([]byte, string) {
		var out []byte
		for {
			res, code := r.call(c, "media.get", map[string]any{"ref": ref, "offset": len(out)})
			if code != "" {
				return nil, code
			}
			part, _ := base64.StdEncoding.DecodeString(res["data"].(string))
			out = append(out, part...)
			if int64(len(out)) >= int64(res["size"].(float64)) {
				return out, ""
			}
			if len(part) == 0 {
				t.Fatalf("empty chunk before the end")
			}
		}
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 6000) // 96,000 bytes, three chunks

	uri, _, err := r.env.Sink.BotIntent().UploadMedia(context.Background(), "", payload, "f.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := sink.MediaRef(uri)
	if !ok || ref[0] != sink.RefCached {
		t.Fatalf("upload ref: %s", uri)
	}
	if got, code := fetch(ref); code != "" || !bytes.Equal(got, payload) {
		t.Fatalf("cached ref: %s", code)
	}

	direct, _ := r.env.Sink.GenerateContentURI(context.Background(), networkid.MediaID("media-1"))
	dref, _ := sink.MediaRef(direct)
	r.download = func(ctx context.Context, id networkid.MediaID) (mediaproxy.GetMediaResponse, error) {
		if string(id) != "media-1" {
			return nil, errors.New("wrong id")
		}
		return &mediaproxy.GetMediaResponseData{Reader: io.NopCloser(bytes.NewReader(payload)), ContentLength: int64(len(payload))}, nil
	}
	if got, code := fetch(dref); code != "" || !bytes.Equal(got, payload) {
		t.Fatalf("direct ref: %s", code)
	}
	if r.downloads != 1 {
		t.Fatalf("direct media fetched %d times for one item", r.downloads)
	}

	fileRef, _ := r.env.Sink.GenerateContentURI(context.Background(), networkid.MediaID("media-file"))
	fref, _ := sink.MediaRef(fileRef)
	r.download = func(ctx context.Context, id networkid.MediaID) (mediaproxy.GetMediaResponse, error) {
		return &mediaproxy.GetMediaResponseFile{Callback: func(f *os.File) (*mediaproxy.FileMeta, error) {
			_, err := f.Write(payload[:1000])
			return &mediaproxy.FileMeta{}, err
		}}, nil
	}
	if got, code := fetch(fref); code != "" || !bytes.Equal(got, payload[:1000]) {
		t.Fatalf("file-response ref: %s", code)
	}

	for i, resp := range []func() mediaproxy.GetMediaResponse{
		func() mediaproxy.GetMediaResponse {
			return &mediaproxy.GetMediaResponseData{Reader: io.NopCloser(bytes.NewReader(nil)), ContentLength: config.MaxMediaBytes + 1}
		},
		func() mediaproxy.GetMediaResponse {
			return &mediaproxy.GetMediaResponseData{Reader: io.NopCloser(io.LimitReader(zeros{}, config.MaxMediaBytes+10)), ContentLength: -1}
		},
		func() mediaproxy.GetMediaResponse {
			return &mediaproxy.GetMediaResponseFile{Callback: func(f *os.File) (*mediaproxy.FileMeta, error) {
				_, err := io.Copy(f, io.LimitReader(zeros{}, config.MaxMediaBytes+10))
				return nil, err
			}}
		},
	} {
		mk := resp
		r.download = func(ctx context.Context, id networkid.MediaID) (mediaproxy.GetMediaResponse, error) { return mk(), nil }
		u, _ := r.env.Sink.GenerateContentURI(context.Background(), networkid.MediaID(fmt.Sprintf("big-%d", i)))
		bref, _ := sink.MediaRef(u)
		r.wantCode(c, "media.get", map[string]any{"ref": bref}, "media_too_large")
	}
	if total := r.env.Media.TotalBytes(); total > 200000 {
		t.Fatalf("refused media left %d bytes in the cache", total)
	}

	r.download = func(ctx context.Context, id networkid.MediaID) (mediaproxy.GetMediaResponse, error) {
		return nil, errors.New("upstream failure with detail")
	}
	u, _ := r.env.Sink.GenerateContentURI(context.Background(), networkid.MediaID("unavailable"))
	uref, _ := sink.MediaRef(u)
	r.wantCode(c, "media.get", map[string]any{"ref": uref}, "media_unavailable")
	r.wantCode(c, "media.get", map[string]any{"ref": "c0123456789abcdef"}, "media_not_found")
	for _, bad := range []string{"", "c", "x1234", "c../../etc/passwd", "cABCDEF", "d!!!", "d"} {
		r.wantCode(c, "media.get", map[string]any{"ref": bad}, "bad_request")
	}
	r.wantCode(c, "media.get", map[string]any{"ref": ref, "offset": -1}, "bad_request")
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func blob(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoginCookies(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	v := r.v.Seal
	login := func(b map[string]any) (map[string]any, string) {
		return r.call(c, "login.cookies", map[string]any{"sealed": b})
	}

	res, code := login(blob(t, v.Blob))
	if code != "" || res["ok"] != true {
		t.Fatalf("login: %v %s", res, code)
	}
	if res["login"].(map[string]any)["id"] != v.Plaintext["c_user"] {
		t.Fatalf("login id: %v", res)
	}
	if len(r.loginSeen) != 1 {
		t.Fatalf("login calls: %d", len(r.loginSeen))
	}
	for name, want := range v.Plaintext {
		if r.loginSeen[0][name] != want {
			t.Fatalf("cookie %s did not reach the connector intact", name)
		}
	}
	if len(r.loginSeen[0]) != len(v.Plaintext) {
		t.Fatalf("unexpected credentials passed: %d", len(r.loginSeen[0]))
	}
	st := r.mustCall(c, "status", map[string]any{})
	if st["login"].(map[string]any)["id"] != v.Plaintext["c_user"] {
		t.Fatalf("status login: %v", st)
	}
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "login" && e.Data["state"] == "linked" })

	if _, code := login(blob(t, v.Blob)); code != "denied_replay" {
		t.Fatalf("replayed handoff: %q", code)
	}
	for name, raw := range map[string]json.RawMessage{
		"instance": v.Variants.OtherInstance, "generation": v.Variants.OtherGeneration,
		"origin": v.Variants.OtherOrigin, "field": v.Variants.OtherField, "audience": v.Variants.OtherAudience,
	} {
		if _, code := login(blob(t, raw)); code != "denied_bound" {
			t.Fatalf("bound %s: %q", name, code)
		}
	}
	tampered := blob(t, v.Variants.Fresh[0])
	tampered["aad"] = strings.Replace(tampered["aad"].(string), "tenant-test", "tenant-tesu", 1)
	if _, code := login(tampered); code != "denied_seal" {
		t.Fatalf("tampered aad: %q", code)
	}
	reordered := blob(t, v.Variants.Fresh[0])
	reordered["aad"] = strings.Replace(reordered["aad"].(string), "{", "{ ", 1)
	if _, code := login(reordered); code != "denied_payload" {
		t.Fatalf("non-canonical aad: %q", code)
	}
	flipped := blob(t, v.Variants.Fresh[0])
	ct := []byte(flipped["ct"].(string))
	ct[0] = "01"[map[bool]int{true: 1}[ct[0] == '0']]
	flipped["ct"] = string(ct)
	if _, code := login(flipped); code != "denied_seal" {
		t.Fatalf("flipped ct: %q", code)
	}
	unknownField := blob(t, v.Variants.Fresh[0])
	unknownField["extra"] = "x"
	if _, code := login(unknownField); code != "bad_request" {
		t.Fatalf("unknown blob field: %q", code)
	}
	if _, code := login(blob(t, v.Variants.ExtraCookie)); code != "denied_payload" {
		t.Fatalf("extra cookie: %q", code)
	}
	if _, code := login(blob(t, v.Variants.MissingXs)); code != "denied_payload" {
		t.Fatalf("missing xs: %q", code)
	}
	// Spent so far: the first login, extraCookie, missingXs. One more fits.
	if _, code := login(blob(t, v.Variants.Fresh[0])); code != "" {
		t.Fatalf("fourth handoff: %q", code)
	}
	if _, code := login(blob(t, v.Variants.Fresh[1])); code != "handoff_limit" {
		t.Fatalf("fifth handoff in a day: %q", code)
	}
	if len(r.loginSeen) != 2 {
		t.Fatalf("refused handoffs reached the connector: %d calls", len(r.loginSeen))
	}
	r.wantCode(c, "login.secret", map[string]any{"sealed": blob(t, v.Variants.Fresh[2])}, "unsupported")
	r.wantCode(c, "login.cookies", map[string]any{}, "bad_request")
	r.noCanaries()
}

func TestLoginFailureCodes(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	for i, tc := range []struct {
		err  error
		code string
	}{
		{loginerrors.Checkpoint, "checkpoint"},
		{fmt.Errorf("%w: %w", loginerrors.Unknown, httpclient.ErrRateLimited), "rate_limited"},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "timeout"},
		{errors.New("CANARY-XS-VALUE inside an upstream error"), "login_failed"},
	} {
		r.mu.Lock()
		r.loginErr = tc.err
		r.mu.Unlock()
		if _, code := r.call(c, "login.cookies", map[string]any{"sealed": blob(t, r.v.Seal.Variants.Fresh[i])}); code != tc.code {
			t.Fatalf("%v: want %s, got %q", tc.err, tc.code, code)
		}
	}
	if st := r.mustCall(c, "status", map[string]any{}); st["login"] != nil {
		t.Fatalf("failed logins left a login: %v", st)
	}
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "login" && e.Data["code"] == "checkpoint" })
	r.noCanaries()
}

func TestLoginRefusals(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	r.loginFake()
	if _, code := r.call(c, "login.cookies", map[string]any{"sealed": blob(t, r.v.Seal.Blob)}); code != "account_mismatch" {
		t.Fatalf("second account: %q", code)
	}

	unconfigured := newRig(t, func(o *core.Options) { o.Seal.Generation = 0 })
	uc := unconfigured.dial()
	unconfigured.wantCode(uc, "login.cookies", map[string]any{"sealed": blob(t, r.v.Seal.Blob)}, "not_configured")

	wrongSealer := newRig(t, func(o *core.Options) { o.Seal.SealerPublic = unhex(t, r.v.KK.KeeperPublic) })
	wc := wrongSealer.dial()
	wrongSealer.wantCode(wc, "login.cookies", map[string]any{"sealed": blob(t, r.v.Seal.Blob)}, "denied_seal")
}

func TestLogout(t *testing.T) {
	r := newRig(t)
	c := r.dial()
	r.loginFake()
	res := r.mustCall(c, "logout", map[string]any{})
	if res["count"] != float64(1) {
		t.Fatalf("logout: %v", res)
	}
	if !r.net.Client.WasLoggedOut() {
		t.Fatalf("the network session was not signed out")
	}
	if st := r.mustCall(c, "status", map[string]any{}); st["login"] != nil {
		t.Fatalf("login survived logout: %v", st)
	}
	r.waitEvent(c, 0, func(e evt) bool { return e.Kind == "login" && e.Data["state"] == "logged_out" })
	r.wantCode(c, "send", map[string]any{"opId": "op-x", "conversation": "t", "text": "x"}, "not_logged_in")
}

var _ = seal.ErrPayload
