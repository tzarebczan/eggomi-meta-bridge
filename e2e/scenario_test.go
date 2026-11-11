// Package e2e drives the whole program (sink, ops, outbox, media, link where
// started) through bridgev2 with a fake network connector. No real account,
// no network: the fake answers sends with success, certain failure or
// timeout to pin the accepted/rejected/unknown mapping.
package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/event"

	"github.com/tzarebczan/eggomi-meta-bridge/ops"
	"github.com/tzarebczan/eggomi-meta-bridge/outbox"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/fakenet"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/harness"
)

const conversation = networkid.PortalID("thread-1")

func pk() networkid.PortalKey {
	return networkid.PortalKey{ID: conversation, Receiver: fakenet.LoginID}
}

// decoded is one journaled event with its data parsed.
type decoded struct {
	outbox.Event
	Data map[string]any
}

func decode(env *harness.Env, after int64) []decoded {
	evts, err := env.Out.Replay(after)
	if err != nil {
		panic(err)
	}
	out := make([]decoded, 0, len(evts))
	for _, e := range evts {
		d := decoded{Event: e}
		if len(e.Data) > 0 {
			_ = json.Unmarshal(e.Data, &d.Data)
		}
		out = append(out, d)
	}
	return out
}

func find(env *harness.Env, pred func(decoded) bool) *decoded {
	for _, d := range decode(env, 0) {
		if pred(d) {
			cp := d
			return &cp
		}
	}
	return nil
}

func waitFor(t *testing.T, env *harness.Env, pred func(decoded) bool, timeout time.Duration) *decoded {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if d := find(env, pred); d != nil {
			return d
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event")
	return nil
}

func ghostMsg(portal networkid.PortalKey, msgID networkid.MessageID, sender networkid.UserID, text string, create bool) *simplevent.PreConvertedMessage {
	return &simplevent.PreConvertedMessage{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventMessage,
			PortalKey:    portal,
			CreatePortal: create,
			Sender:       bridgev2.EventSender{Sender: sender},
			Timestamp:    time.Now(),
		},
		ID: msgID,
		Data: &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{{
				Type:    event.EventMessage,
				Content: &event.MessageEventContent{MsgType: event.MsgText, Body: text},
			}},
		},
	}
}

// TestScenario drives every bridgev2 path the Messenger connector uses
// through the program. One bridge, subtests in order.
func TestScenario(t *testing.T) {
	net := fakenet.New()
	env := harness.New(t, net)
	ctx := context.Background()

	login, err := env.Login(ctx, fakenet.LoginID, "Owner")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	roomID := env.Sink.GenerateDeterministicRoomID(pk())

	t.Run("inbound message lands as item", func(t *testing.T) {
		login.QueueRemoteEvent(ghostMsg(pk(), "msg-1", "ghost-1", "hello from ghost", true))
		item := waitFor(t, env, func(d decoded) bool {
			return d.Kind == "item" && d.Data["text"] == "hello from ghost" && d.Portal == string(conversation)
		}, 10*time.Second)
		if item.Data["remoteId"] != "msg-1" || item.Data["sender"] != "ghost-1" {
			t.Fatalf("item fields: %v", item.Data)
		}
		conv := find(env, func(d decoded) bool {
			return d.Kind == "conversation" && d.Data["room"] == string(roomID)
		})
		if conv == nil {
			t.Fatalf("portal creation did not use the deterministic room id")
		}
		if conv.Portal != string(conversation) {
			t.Fatalf("conversation event names %q, not the remote conversation", conv.Portal)
		}
	})

	t.Run("message row resolvable by remote id", func(t *testing.T) {
		row, err := env.Bridge.DB.Message.GetPartByID(ctx, fakenet.LoginID, "msg-1", "")
		if err != nil || row == nil || row.MXID == "" {
			t.Fatalf("row: %v %v", row, err)
		}
	})

	t.Run("retransmission deduped", func(t *testing.T) {
		before := len(decode(env, 0))
		login.QueueRemoteEvent(ghostMsg(pk(), "msg-1", "ghost-1", "hello from ghost", false))
		time.Sleep(700 * time.Millisecond)
		for _, d := range decode(env, 0)[before:] {
			if d.Kind == "item" {
				t.Fatalf("duplicate item journaled: %v", d.Data)
			}
		}
	})

	t.Run("edit lands with target", func(t *testing.T) {
		login.QueueRemoteEvent(&simplevent.Message[any]{
			EventMeta:     simplevent.EventMeta{Type: bridgev2.RemoteEventEdit, PortalKey: pk(), Sender: bridgev2.EventSender{Sender: "ghost-1"}, Timestamp: time.Now()},
			TargetMessage: "msg-1",
			ConvertEditFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data any) (*bridgev2.ConvertedEdit, error) {
				part := &bridgev2.ConvertedEditPart{
					Type:    event.EventMessage,
					Content: &event.MessageEventContent{MsgType: event.MsgText, Body: "edited text"},
				}
				if len(existing) > 0 {
					part.Part = existing[0]
				}
				return &bridgev2.ConvertedEdit{ModifiedParts: []*bridgev2.ConvertedEditPart{part}}, nil
			},
		})
		edit := waitFor(t, env, func(d decoded) bool {
			return d.Kind == "edit" && d.Data["text"] == "edited text"
		}, 5*time.Second)
		if edit.Data["targetId"] != "msg-1" {
			t.Fatalf("edit target resolution: %v", edit.Data)
		}
	})

	t.Run("reaction lands", func(t *testing.T) {
		login.QueueRemoteEvent(&simplevent.Reaction{
			EventMeta:     simplevent.EventMeta{Type: bridgev2.RemoteEventReaction, PortalKey: pk(), Sender: bridgev2.EventSender{Sender: "ghost-1"}, Timestamp: time.Now()},
			TargetMessage: "msg-1", Emoji: "\U0001F44D", EmojiID: "\U0001F44D",
		})
		// bridgev2 adds U+FE0F; match the base emoji.
		react := waitFor(t, env, func(d decoded) bool {
			emoji, _ := d.Data["emoji"].(string)
			return d.Kind == "reaction" && strings.HasPrefix(emoji, "\U0001F44D")
		}, 5*time.Second)
		if react.Data["targetId"] != "msg-1" || !strings.HasPrefix(react.Data["eventId"].(string), "$mbr-") {
			t.Fatalf("reaction fields: %v", react.Data)
		}
	})

	t.Run("reaction removal lands", func(t *testing.T) {
		login.QueueRemoteEvent(&simplevent.Reaction{
			EventMeta:     simplevent.EventMeta{Type: bridgev2.RemoteEventReactionRemove, PortalKey: pk(), Sender: bridgev2.EventSender{Sender: "ghost-1"}, Timestamp: time.Now()},
			TargetMessage: "msg-1", EmojiID: "\U0001F44D",
		})
		waitFor(t, env, func(d decoded) bool { return d.Kind == "reaction_remove" }, 5*time.Second)
	})

	t.Run("remote read receipt lands", func(t *testing.T) {
		login.QueueRemoteEvent(&simplevent.Receipt{
			EventMeta:  simplevent.EventMeta{Type: bridgev2.RemoteEventReadReceipt, PortalKey: pk(), Sender: bridgev2.EventSender{IsFromMe: true}, Timestamp: time.Now()},
			LastTarget: "msg-1", ReadUpTo: time.Now(),
		})
		read := waitFor(t, env, func(d decoded) bool { return d.Kind == "read" }, 5*time.Second)
		if read.Data["upToId"] != "msg-1" {
			t.Fatalf("read upTo resolution: %v", read.Data)
		}
	})

	waitOp := func(opID string) *decoded {
		return waitFor(t, env, func(d decoded) bool {
			return d.Kind == "op" && d.Data["opId"] == opID && d.Data["state"] != ops.StateCommitted
		}, 15*time.Second)
	}

	t.Run("send accepted with provider id", func(t *testing.T) {
		if err := env.Sink.SendText(ctx, login, "op-1", conversation, "hello from owner", ""); err != nil {
			t.Fatalf("send: %v", err)
		}
		op := waitOp("op-1")
		if op.Data["state"] != ops.StateAccepted || op.Data["remoteId"] != "remote-op-1" {
			t.Fatalf("op settle: %v", op.Data)
		}
	})

	t.Run("duplicate op id refused", func(t *testing.T) {
		before := len(net.Client.SentRecords())
		if err := env.Sink.SendText(ctx, login, "op-1", conversation, "hello from owner", ""); err == nil {
			t.Fatalf("duplicate op id accepted")
		}
		if len(net.Client.SentRecords()) != before {
			t.Fatalf("duplicate op reached the network")
		}
	})

	t.Run("certain failure rejected", func(t *testing.T) {
		net.Client.Mode = fakenet.ModeFailCertain
		defer func() { net.Client.Mode = fakenet.ModeOK }()
		if err := env.Sink.SendText(ctx, login, "op-2", conversation, "will be refused", ""); err != nil {
			t.Fatalf("send: %v", err)
		}
		if op := waitOp("op-2"); op.Data["state"] != ops.StateRejected {
			t.Fatalf("op settle: %v", op.Data)
		}
	})

	t.Run("post-commit timeout is unknown", func(t *testing.T) {
		net.Client.Mode = fakenet.ModeTimeout
		defer func() { net.Client.Mode = fakenet.ModeOK }()
		if err := env.Sink.SendText(ctx, login, "op-3", conversation, "maybe sent", ""); err != nil {
			t.Fatalf("send: %v", err)
		}
		if op := waitOp("op-3"); op.Data["state"] != ops.StateUnknown {
			t.Fatalf("op settle: %v", op.Data)
		}
	})

	t.Run("reaction send accepted", func(t *testing.T) {
		if err := env.Sink.SendReaction(ctx, login, "op-4", conversation, "msg-1", "\U0001F44D"); err != nil {
			t.Fatalf("react: %v", err)
		}
		if op := waitOp("op-4"); op.Data["state"] != ops.StateAccepted {
			t.Fatalf("op settle: %v", op.Data)
		}
	})

	t.Run("reaction remove reaches network", func(t *testing.T) {
		if err := env.Sink.RemoveReaction(ctx, login, "op-5", conversation, "msg-1"); err != nil {
			t.Fatalf("unreact: %v", err)
		}
		waitOp("op-5")
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, r := range net.Client.SentRecords() {
				if r.Kind == "reaction_remove" {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("network never saw the removal")
	})

	t.Run("markRead reaches network", func(t *testing.T) {
		if err := env.Sink.MarkRead(ctx, login, conversation, "msg-1"); err != nil {
			t.Fatalf("markRead: %v", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, r := range net.Client.SentRecords() {
				if r.Kind == "read_receipt" {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("network never saw the receipt")
	})

	t.Run("message delete lands", func(t *testing.T) {
		login.QueueRemoteEvent(&simplevent.MessageRemove{
			EventMeta:     simplevent.EventMeta{Type: bridgev2.RemoteEventMessageRemove, PortalKey: pk(), Sender: bridgev2.EventSender{Sender: "ghost-1"}, Timestamp: time.Now()},
			TargetMessage: "msg-1",
		})
		del := waitFor(t, env, func(d decoded) bool { return d.Kind == "delete" }, 5*time.Second)
		if del.Data["targetId"] != "msg-1" {
			t.Fatalf("delete target resolution: %v", del.Data)
		}
	})

	t.Run("batch backfill maps to history items", func(t *testing.T) {
		meta := &database.Message{ID: "msg-old-1", SenderID: "ghost-1", Timestamp: time.Now().Add(-time.Hour)}
		_, err := env.Sink.BatchSend(ctx, roomID, &mautrix.ReqBeeperBatchSend{
			Events: []*event.Event{{
				Type:    event.EventMessage,
				Content: event.Content{Parsed: &event.MessageEventContent{MsgType: event.MsgText, Body: "old message"}},
			}},
		}, []*bridgev2.MatrixSendExtra{{MessageMeta: meta}})
		if err != nil {
			t.Fatalf("batch send: %v", err)
		}
		waitFor(t, env, func(d decoded) bool {
			return d.Kind == "item" && d.Data["source"] == "history" && d.Data["text"] == "old message"
		}, 5*time.Second)
	})

	t.Run("reply to unknown target is target_gone", func(t *testing.T) {
		err := env.Sink.SendText(ctx, login, "op-6", conversation, "reply", "no-such-message")
		if err != sink.ErrTargetGone {
			t.Fatalf("want target_gone, got %v", err)
		}
		if row, _ := env.Ops.Get(ctx, "op-6"); row != nil {
			t.Fatalf("op was committed despite early refusal: %v", row)
		}
	})

	t.Run("unknown conversation refused", func(t *testing.T) {
		err := env.Sink.SendText(ctx, login, "op-7", "no-such-thread", "hi", "")
		if err != sink.ErrUnknownConversation {
			t.Fatalf("want unknown_conversation, got %v", err)
		}
	})

	t.Run("reconcile finds a sent message", func(t *testing.T) {
		op, err := env.Sink.Reconcile(ctx, "op-1")
		if err != nil || op == nil {
			t.Fatalf("reconcile: %v %v", op, err)
		}
		if op.State != ops.StateAccepted || op.RemoteID != "remote-op-1" {
			t.Fatalf("reconcile state: %v", op)
		}
	})
}

// TestRestartSettlesCommittedUnknown: an operation found at the commit point
// on boot (a crash took the process between Begin and settle) is unknown
// (PROTOCOL.md section 5.1), and the op event is journaled.
func TestRestartSettlesCommittedUnknown(t *testing.T) {
	net := fakenet.New()
	env := harness.New(t, net)
	ctx := context.Background()
	if _, err := env.Login(ctx, fakenet.LoginID, "Owner"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := env.Ops.Begin(ctx, "op-crash", "send", string(conversation), "digest"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	dir := env.Dir
	env.Bridge.Stop()
	env.DB.Close()

	env2, err := harness.Start(dir, fakenet.New(), zerologNop())
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer env2.Bridge.Stop()
	defer env2.DB.Close()
	op, err := env2.Ops.Get(ctx, "op-crash")
	if err != nil || op == nil {
		t.Fatalf("op lost across restart: %v", err)
	}
	if op.State != ops.StateUnknown || op.Code != "bridge_restarted" {
		t.Fatalf("op after restart: %+v", op)
	}
	evt := find(env2, func(d decoded) bool {
		return d.Kind == "op" && d.Data["opId"] == "op-crash" && d.Data["state"] == ops.StateUnknown
	})
	if evt == nil {
		t.Fatalf("no op event journaled for the recovered op")
	}
}

// TestOutboxReplayAcrossRestart: journaled events survive a restart; ack
// deletes only up to the acked seq; replay starts after it (PROTOCOL.md section 3).
func TestOutboxReplayAcrossRestart(t *testing.T) {
	net := fakenet.New()
	env := harness.New(t, net)
	ctx := context.Background()
	login, err := env.Login(ctx, fakenet.LoginID, "Owner")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	login.QueueRemoteEvent(ghostMsg(pk(), "msg-r1", "ghost-1", "before restart", true))
	item := waitFor(t, env, func(d decoded) bool {
		return d.Kind == "item" && d.Data["remoteId"] == "msg-r1"
	}, 10*time.Second)
	seqAtItem := item.Seq

	dir := env.Dir
	env.Bridge.Stop()
	env.DB.Close()
	env2, err := harness.Start(dir, fakenet.New(), zerologNop())
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer env2.Bridge.Stop()
	defer env2.DB.Close()

	replayed := find(env2, func(d decoded) bool {
		return d.Kind == "item" && d.Data["remoteId"] == "msg-r1" && d.Seq == seqAtItem
	})
	if replayed == nil {
		t.Fatalf("journaled item lost across restart")
	}
	if err := env2.Out.Ack(seqAtItem); err != nil {
		t.Fatalf("ack: %v", err)
	}
	for _, d := range decode(env2, 0) {
		if d.Seq <= seqAtItem {
			t.Fatalf("acked event %d still journaled", d.Seq)
		}
	}
}
