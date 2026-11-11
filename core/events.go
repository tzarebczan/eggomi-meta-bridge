package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/tzarebczan/eggomi-meta-bridge/link"
)

type loginInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type statusResult struct {
	Epoch    string     `json:"epoch"`
	Latest   int64      `json:"latest"`
	Pending  int        `json:"pending"`
	State    string     `json:"state"`
	Error    string     `json:"error,omitempty"`
	Login    *loginInfo `json:"login"`
	Version  string     `json:"version"`
	Upstream string     `json:"upstream"`
}

func (c *Core) status(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct{}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	pending, err := c.o.Out.Count(ctx)
	if err != nil {
		return nil, err
	}
	st := c.o.Sink.State()
	res := &statusResult{
		Epoch:    c.o.Out.Epoch(),
		Latest:   c.o.Out.Latest(),
		Pending:  pending,
		State:    string(st.StateEvent),
		Error:    string(st.Error),
		Version:  c.o.Version,
		Upstream: c.o.Upstream,
	}
	if res.State == "" {
		res.State = "STARTING"
	}
	if user, err := c.owner(ctx); err == nil {
		if ul := user.GetDefaultLogin(); ul != nil {
			res.Login = &loginInfo{ID: string(ul.ID), Name: ul.RemoteName}
		}
	}
	return res, nil
}

type eventStub struct {
	Seq     int64  `json:"seq"`
	Kind    string `json:"kind"`
	Portal  string `json:"portal,omitempty"`
	Size    int    `json:"size"`
	Chunked bool   `json:"chunked"`
}

// eventsNext is the keeper's long poll: events after its cursor, waiting up
// to waitMs for the first one. An event too large for one frame arrives as
// a stub and is fetched with events.chunk.
func (c *Core) eventsNext(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		After  int64 `json:"after"`
		WaitMs int64 `json:"waitMs"`
		Limit  int   `json:"limit"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if p.After < 0 || p.WaitMs < 0 || p.WaitMs > MaxWait.Milliseconds() || p.Limit < 0 || p.Limit > MaxEventLimit {
		return nil, errBadRequest
	}
	if p.Limit == 0 {
		p.Limit = DefaultEventLimit
	}
	if p.After > c.o.Out.Latest() {
		// The cursor is from a wiped store (see epoch); the keeper restarts at 0.
		return nil, link.Code("cursor_ahead")
	}
	if p.WaitMs > 0 {
		wctx, cancel := context.WithTimeout(ctx, time.Duration(p.WaitMs)*time.Millisecond)
		err := c.o.Out.Wait(wctx, p.After)
		cancel()
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	evts, err := c.o.Out.Page(p.After, p.Limit)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(evts))
	used, more := 0, false
	for i, e := range evts {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		if used+len(raw)+1 > eventBudget {
			if i == 0 {
				stub, _ := json.Marshal(eventStub{Seq: e.Seq, Kind: e.Kind, Portal: e.Portal, Size: len(raw), Chunked: true})
				out = append(out, stub)
			}
			more = true
			break
		}
		used += len(raw) + 1
		out = append(out, raw)
	}
	if !more && len(evts) == p.Limit {
		more = c.o.Out.Latest() > evts[len(evts)-1].Seq
	}
	return map[string]any{
		"epoch":  c.o.Out.Epoch(),
		"events": out,
		"latest": c.o.Out.Latest(),
		"more":   more,
	}, nil
}

// eventsChunk returns a slice of one event's JSON encoding (the same object
// events.next would have carried), base64.
func (c *Core) eventsChunk(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Seq    int64 `json:"seq"`
		Offset int   `json:"offset"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if p.Seq <= 0 || p.Offset < 0 {
		return nil, errBadRequest
	}
	e, err := c.o.Out.Get(p.Seq)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, link.Code("gone")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if p.Offset > len(raw) {
		return nil, errBadRequest
	}
	end := min(p.Offset+ChunkBytes, len(raw))
	return map[string]any{
		"seq":    p.Seq,
		"size":   len(raw),
		"offset": p.Offset,
		"data":   base64.StdEncoding.EncodeToString(raw[p.Offset:end]),
	}, nil
}

// ack drops journaled events up to seq; the keeper sends it only after its
// records and cursor are committed.
func (c *Core) ack(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Seq *int64 `json:"seq"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if p.Seq == nil || *p.Seq < 0 {
		return nil, errBadRequest
	}
	if *p.Seq > c.o.Out.Latest() {
		return nil, link.Code("cursor_ahead")
	}
	if err := c.o.Out.Ack(*p.Seq); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}
