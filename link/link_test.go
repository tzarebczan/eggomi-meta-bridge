package link

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rs/zerolog"
)

type kkVectors struct {
	KK struct {
		Prologue        string `json:"prologue"`
		KeeperStatic    string `json:"keeperStatic"`
		KeeperPublic    string `json:"keeperPublic"`
		BridgeStatic    string `json:"bridgeStatic"`
		BridgePublic    string `json:"bridgePublic"`
		BridgeEphemeral string `json:"bridgeEphemeral"`
		HelloFrame      string `json:"helloFrame"`
		Message2        string `json:"message2"`
		Request         string `json:"request"`
		RequestCipher   string `json:"requestCiphertext"`
		Reply           string `json:"reply"`
		ReplyCiphertext string `json:"replyCiphertext"`
	} `json:"kk"`
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKeeperVectors: given the keeper's first message (made by its
// noise.mjs KkInitiator) and the same ephemeral key, this responder writes
// byte-identical second message and transport ciphertexts.
func TestKeeperVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var v kkVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.KK.Prologue != string(Prologue) {
		t.Fatalf("prologue drift: %q", v.KK.Prologue)
	}
	if pub, _ := PublicKey(h(t, v.KK.BridgeStatic)); hex.EncodeToString(pub) != v.KK.BridgePublic {
		t.Fatalf("public key derivation differs")
	}
	frame, err := ReadFrame(bytes.NewReader(h(t, v.KK.HelloFrame)))
	if err != nil || frame[0] != hello {
		t.Fatalf("hello frame: %v", err)
	}
	msg2, recv, send, err := Respond(h(t, v.KK.BridgeStatic), h(t, v.KK.KeeperPublic), bytes.NewReader(h(t, v.KK.BridgeEphemeral)), frame[1:])
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	if hex.EncodeToString(msg2) != v.KK.Message2 {
		t.Fatalf("message2 differs from the keeper's responder")
	}
	pt, err := recv.Decrypt(nil, nil, h(t, v.KK.RequestCipher))
	if err != nil || string(pt) != v.KK.Request {
		t.Fatalf("request decrypt: %q %v", pt, err)
	}
	ct, err := send.Encrypt(nil, nil, []byte(v.KK.Reply))
	if err != nil || hex.EncodeToString(ct) != v.KK.ReplyCiphertext {
		t.Fatalf("reply ciphertext differs")
	}
}

func keys(t *testing.T) (bridgePriv, bridgePub, keeperPriv, keeperPub []byte) {
	t.Helper()
	gen := func() ([]byte, []byte) {
		kp, err := noise.DH25519.GenerateKeypair(nil)
		if err != nil {
			t.Fatal(err)
		}
		return kp.Private, kp.Public
	}
	bridgePriv, bridgePub = gen()
	keeperPriv, keeperPub = gen()
	return
}

func startServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if s.Log.GetLevel() == zerolog.TraceLevel {
		s.Log = zerolog.Nop()
	}
	go s.Serve(ln)
	t.Cleanup(s.Close)
	return ln.Addr().String()
}

func echoHandler() HandlerFunc {
	return func(ctx context.Context, method string, params json.RawMessage) (any, error) {
		switch method {
		case "health":
			return map[string]any{"ok": true}, nil
		case "echo":
			var p map[string]any
			json.Unmarshal(params, &p)
			return p, nil
		case "fail":
			return nil, Code("target_gone")
		case "boom":
			return nil, errors.New("internal detail that must not leave")
		case "panic":
			panic("handler bug")
		case "big":
			return strings.Repeat("x", MaxPayload), nil
		case "null":
			return nil, nil
		case "wait":
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, Code("unknown_method")
	}
}

func TestRoundTripAndCodes(t *testing.T) {
	bp, bpub, kp, _ := keys(t)
	kpub, _ := PublicKey(kp)
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: echoHandler(), Log: zerolog.Nop()})
	c, err := Dial(addr, kp, bpub)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	var health map[string]any
	if err := c.Call("health", map[string]any{}, &health); err != nil || health["ok"] != true {
		t.Fatalf("health: %v %v", health, err)
	}
	var echo map[string]any
	if err := c.Call("echo", map[string]any{"a": "b"}, &echo); err != nil || echo["a"] != "b" {
		t.Fatalf("echo: %v %v", echo, err)
	}
	var re *RemoteError
	if err := c.Call("fail", nil, nil); !errors.As(err, &re) || re.Code != "target_gone" {
		t.Fatalf("coded error: %v", err)
	}
	if err := c.Call("boom", nil, nil); !errors.As(err, &re) || re.Code != "error" {
		t.Fatalf("uncoded error must be 'error': %v", err)
	}
	if err := c.Call("panic", nil, nil); !errors.As(err, &re) || re.Code != "error" {
		t.Fatalf("panic must be 'error': %v", err)
	}
	if err := c.Call("big", nil, nil); !errors.As(err, &re) || re.Code != "error" {
		t.Fatalf("oversize reply must be 'error': %v", err)
	}
	var null any = "unset"
	if err := c.Call("null", nil, &null); err != nil {
		t.Fatalf("null result: %v", err)
	}
	// the channel still works after all of the above
	if err := c.Call("health", nil, &health); err != nil {
		t.Fatalf("channel broken after errors: %v", err)
	}
}

func TestOnlyPinnedKeeperCompletesHandshake(t *testing.T) {
	bp, bpub, _, kpub := keys(t)
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: echoHandler(), Log: zerolog.Nop()})
	_, _, stranger, _ := keys(t)
	c, err := Dial(addr, stranger, bpub)
	if err == nil {
		// KK: the initiator cannot detect a wrong responder view until it
		// reads; the server must have closed before answering anything.
		callErr := c.Call("health", nil, nil)
		c.Close()
		if callErr == nil {
			t.Fatalf("an unpinned key got a channel")
		}
	}
}

func TestHandshakeTimeout(t *testing.T) {
	bp, _, _, kpub := keys(t)
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: echoHandler(), Log: zerolog.Nop(), HandshakeTimeout: 200 * time.Millisecond})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("silent socket got data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server did not close a silent socket")
	}
}

func TestMaxConns(t *testing.T) {
	bp, bpub, kp, _ := keys(t)
	kpub, _ := PublicKey(kp)
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: echoHandler(), Log: zerolog.Nop(), MaxConns: 2})
	var open []*Client
	for i := 0; i < 2; i++ {
		c, err := Dial(addr, kp, bpub)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		open = append(open, c)
	}
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	if c, err := Dial(addr, kp, bpub); err == nil {
		c.Close()
		t.Fatalf("third connection admitted over MaxConns=2")
	}
}

// TestCloseCancelsHandler: a long poll learns the keeper is gone.
func TestCloseCancelsHandler(t *testing.T) {
	bp, bpub, kp, _ := keys(t)
	kpub, _ := PublicKey(kp)
	cancelled := make(chan struct{})
	h := HandlerFunc(func(ctx context.Context, method string, params json.RawMessage) (any, error) {
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: h, Log: zerolog.Nop()})
	c, err := Dial(addr, kp, bpub)
	if err != nil {
		t.Fatal(err)
	}
	go c.Call("wait", nil, nil)
	time.Sleep(100 * time.Millisecond)
	c.Close()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatalf("handler context not cancelled after close")
	}
}

// TestKeeperClient: the Eggomi keeper's own openChannel (cah.mjs) completes
// the handshake and calls this server. Runs when EGGOMI_REPO points at an
// Eggomi checkout and node is installed.
func TestKeeperClient(t *testing.T) {
	repo := os.Getenv("EGGOMI_REPO")
	if repo == "" {
		t.Skip("EGGOMI_REPO not set")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	bp, bpub, kp, _ := keys(t)
	kpub, _ := PublicKey(kp)
	addr := startServer(t, &Server{StaticPrivate: bp, KeeperPublic: kpub, Handler: echoHandler(), Log: zerolog.Nop()})
	host, port, _ := net.SplitHostPort(addr)
	script := `
import net from "node:net";
import { pathToFileURL } from "node:url";
const [repo, host, port, kp, bpub] = process.argv.slice(2);
const { openChannel } = await import(pathToFileURL(repo + "/infra/dstack/keeper/cah.mjs").href);
const socket = net.connect(Number(port), host);
await new Promise((r) => socket.once("connect", r));
const ch = await openChannel(socket, { staticPrivateKey: Buffer.from(kp, "hex"), keeperPublic: Buffer.from(bpub, "hex") });
const health = await ch.call("health", {});
const echo = await ch.call("echo", { text: "héllo ✓" });
let code = null;
try { await ch.call("fail", {}); } catch (e) { code = e.code; }
ch.close();
process.stdout.write(JSON.stringify({ health, echo, code }));
`
	dir := t.TempDir()
	path := filepath.Join(dir, "client.mjs")
	os.WriteFile(path, []byte(script), 0o600)
	out, err := exec.Command("node", path, repo, host, port, hex.EncodeToString(kp), hex.EncodeToString(bpub)).CombinedOutput()
	if err != nil {
		t.Fatalf("node client: %v\n%s", err, out)
	}
	var got struct {
		Health map[string]any `json:"health"`
		Echo   map[string]any `json:"echo"`
		Code   string         `json:"code"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("node output %q: %v", out, err)
	}
	if got.Health["ok"] != true || got.Echo["text"] != "héllo ✓" {
		t.Fatalf("node round trip: %+v", got)
	}
	// cah.mjs remoteCode maps codes outside its allow-list to a generic one;
	// any non-empty code proves the error frame parsed.
	if got.Code == "" {
		t.Fatalf("node client saw no error code")
	}
}
