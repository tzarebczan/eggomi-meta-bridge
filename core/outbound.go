package core

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/tzarebczan/eggomi-meta-bridge/link"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
)

// opResult answers send and react: the stored row, and whether this op id
// had already been committed (nothing was sent again).
func (c *Core) opResult(ctx context.Context, opID string, err error) (any, error) {
	duplicate := errors.Is(err, sink.ErrDuplicateOp)
	if err != nil && !duplicate {
		return nil, outboundCode(err)
	}
	op, gerr := c.o.Ops.Get(ctx, opID)
	if gerr != nil {
		return nil, gerr
	}
	if op == nil {
		return nil, errors.New("committed op missing")
	}
	return map[string]any{"op": op, "duplicate": duplicate}, nil
}

// send commits one text message (PROTOCOL.md section 5). The answer is the op row at the
// commit point; the outcome arrives as an op event.
func (c *Core) send(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		OpID         string `json:"opId"`
		Conversation string `json:"conversation"`
		Text         string `json:"text"`
		ReplyTo      string `json:"replyTo"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validOpID(p.OpID) || !validID(p.Conversation) || !validText(p.Text) || (p.ReplyTo != "" && !validID(p.ReplyTo)) {
		return nil, errBadRequest
	}
	ul, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	err = c.o.Sink.SendText(ctx, ul, p.OpID, networkid.PortalID(p.Conversation), p.Text, networkid.MessageID(p.ReplyTo))
	return c.opResult(ctx, p.OpID, err)
}

// react adds the owner's reaction, or removes the owner's newest reaction to
// the item when emoji is null.
func (c *Core) react(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		OpID         string  `json:"opId"`
		Conversation string  `json:"conversation"`
		Item         string  `json:"item"`
		Emoji        *string `json:"emoji"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validOpID(p.OpID) || !validID(p.Conversation) || !validID(p.Item) || (p.Emoji != nil && !validEmoji(*p.Emoji)) {
		return nil, errBadRequest
	}
	ul, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	conv, item := networkid.PortalID(p.Conversation), networkid.MessageID(p.Item)
	if p.Emoji == nil {
		err = c.o.Sink.RemoveReaction(ctx, ul, p.OpID, conv, item)
	} else {
		err = c.o.Sink.SendReaction(ctx, ul, p.OpID, conv, item, *p.Emoji)
	}
	return c.opResult(ctx, p.OpID, err)
}

// markRead sends the owner's read receipt up to an item.
func (c *Core) markRead(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Conversation string `json:"conversation"`
		UpTo         string `json:"upTo"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validID(p.Conversation) || !validID(p.UpTo) {
		return nil, errBadRequest
	}
	ul, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.o.Sink.MarkRead(ctx, ul, networkid.PortalID(p.Conversation), networkid.MessageID(p.UpTo)); err != nil {
		return nil, outboundCode(err)
	}
	return map[string]any{"ok": true}, nil
}

// older queues one page of older history for a conversation.
// The page arrives as item events with source "history"; queued false means
// there is no older history left.
func (c *Core) older(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Conversation string `json:"conversation"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validID(p.Conversation) {
		return nil, errBadRequest
	}
	ul, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := ul.Client.(bridgev2.BackfillingNetworkAPI); !ok {
		return nil, link.Code("unsupported")
	}
	key := networkid.PortalKey{ID: networkid.PortalID(p.Conversation), Receiver: ul.ID}
	portal, err := c.o.Bridge.GetExistingPortalByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if portal == nil || portal.MXID == "" {
		return nil, link.Code("unknown_conversation")
	}
	task, err := c.o.Bridge.DB.BackfillTask.GetNextForPortal(ctx, key, false)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return map[string]any{"queued": false}, nil
	}
	c.olderMu.Lock()
	if last, ok := c.olderLast[key.ID]; ok && time.Since(last) < c.o.OlderSpacing {
		c.olderMu.Unlock()
		return nil, link.Code("busy")
	}
	c.olderLast[key.ID] = time.Now()
	c.olderMu.Unlock()
	c.o.Bridge.WakeupBackfillQueue(&bridgev2.ManualBackfill{Source: ul, Portal: portal})
	return map[string]any{"queued": true}, nil
}

// reconcile re-checks an unknown op against the bridge's message table
// (PROTOCOL.md section 5.2), read-only toward the network.
func (c *Core) reconcile(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		OpID string `json:"opId"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validOpID(p.OpID) {
		return nil, errBadRequest
	}
	op, err := c.o.Sink.Reconcile(ctx, p.OpID)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, link.Code("unknown_op")
	}
	return map[string]any{"op": op}, nil
}

// op reads one op row (null when the op id is unknown).
func (c *Core) op(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		OpID string `json:"opId"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !validOpID(p.OpID) {
		return nil, errBadRequest
	}
	op, err := c.o.Ops.Get(ctx, p.OpID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"op": op}, nil
}
