// Package core answers the keeper's link requests (PROTOCOL.md) on top of
// the sink, the op table, the outbox and the media cache. Every answer is a
// result or a coded error; parameters are never logged, and nothing a
// request carried (message text, cookies, media) appears in an error.
package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/mediaproxy"

	"github.com/tzarebczan/eggomi-meta-bridge/link"
	"github.com/tzarebczan/eggomi-meta-bridge/media"
	"github.com/tzarebczan/eggomi-meta-bridge/ops"
	"github.com/tzarebczan/eggomi-meta-bridge/outbox"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
)

// Limits (PROTOCOL.md section 9).
const (
	MaxTextRunes      = 20000
	MaxIDBytes        = 256
	MaxEmojiBytes     = 32
	MaxWait           = 30 * time.Second
	DefaultEventLimit = 200
	MaxEventLimit     = 500
	// ChunkBytes is the raw size of one media or event chunk; base64 of it
	// plus the reply envelope stays well inside one link frame.
	ChunkBytes = 32 << 10
	// eventBudget bounds the encoded events in one events.next answer.
	eventBudget = link.MaxPayload - 1024
	// OlderSpacing is the minimum gap between two older requests for one
	// conversation; the keeper's own limit is 30 an hour.
	OlderSpacing = 10 * time.Second
	LoginTimeout = 90 * time.Second
	MediaTimeout = 2 * time.Minute
)

// SealConfig is what a login.cookies blob must be bound to.
type SealConfig struct {
	BridgePrivate []byte // this bridge's static link key, the seal's recipient
	SealerPublic  []byte // the guard's pinned static key
	Audience      string // hex of the keeper's channel key
	Instance      string // recipient_instance
	Generation    int64  // recipient_generation
}

// Options wires a Core.
type Options struct {
	Bridge *bridgev2.Bridge
	Sink   *sink.Sink
	Out    *outbox.Outbox
	Ops    *ops.Table
	Media  *media.Cache
	DB     *sql.DB // the program's store, for the used-grant table

	// Login creates the user login from cookie credentials
	// (MetaConnector.CreateUserLoginFromCredentials).
	Login func(ctx context.Context, user *bridgev2.User, creds map[string]any) error
	// LoginID names the login the credentials belong to (one account per
	// computer: a different account is refused while one is linked).
	LoginID func(creds map[string]any) networkid.UserLoginID
	// Download fetches direct media (MetaConnector.Download). nil: direct
	// refs answer media_unavailable.
	Download func(ctx context.Context, mediaID networkid.MediaID, params map[string]string) (mediaproxy.GetMediaResponse, error)
	// MaxMedia is the per-item media limit in bytes.
	MaxMedia int64
	// OlderSpacing overrides the default gap between older requests for one
	// conversation (tests).
	OlderSpacing time.Duration

	Seal     SealConfig
	Log      zerolog.Logger
	Version  string // this program's version
	Upstream string // the mautrix-meta commit it is built from
}

// Core is the link Handler.
type Core struct {
	o       Options
	loginMu sync.Mutex
	mediaMu sync.Mutex

	olderMu   sync.Mutex
	olderLast map[networkid.PortalID]time.Time
}

const grantSchema = `
CREATE TABLE IF NOT EXISTS used_grants (
	grant_hash TEXT PRIMARY KEY,
	used_at    INTEGER NOT NULL
);
`

// New builds the handler and its tables.
func New(o Options) (*Core, error) {
	if o.Bridge == nil || o.Sink == nil || o.Out == nil || o.Ops == nil || o.Media == nil || o.DB == nil {
		return nil, fmt.Errorf("core: missing component")
	}
	if o.MaxMedia <= 0 {
		return nil, fmt.Errorf("core: MaxMedia must be set")
	}
	if o.OlderSpacing <= 0 {
		o.OlderSpacing = OlderSpacing
	}
	if _, err := o.DB.Exec(grantSchema); err != nil {
		return nil, fmt.Errorf("used_grants schema: %w", err)
	}
	return &Core{o: o, olderLast: map[networkid.PortalID]time.Time{}}, nil
}

// Handle implements link.Handler.
func (c *Core) Handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	h, ok := methods[method]
	if !ok {
		return nil, link.Code("unknown_method")
	}
	res, err := h(c, ctx, params)
	if err != nil {
		var le *link.Error
		if !errors.As(err, &le) {
			// Internal detail stays here; the keeper sees "error".
			c.o.Log.Warn().Str("method", method).Err(err).Msg("request failed")
			return nil, link.Code("error")
		}
		c.o.Log.Debug().Str("method", method).Str("code", le.Code).Msg("request refused")
	}
	return res, err
}

type handler func(c *Core, ctx context.Context, params json.RawMessage) (any, error)

var methods = map[string]handler{
	"status":        (*Core).status,
	"events.next":   (*Core).eventsNext,
	"events.chunk":  (*Core).eventsChunk,
	"ack":           (*Core).ack,
	"login.cookies": (*Core).loginCookies,
	"login.secret":  (*Core).loginSecret,
	"logout":        (*Core).logout,
	"send":          (*Core).send,
	"react":         (*Core).react,
	"markRead":      (*Core).markRead,
	"older":         (*Core).older,
	"media.get":     (*Core).mediaGet,
	"reconcile":     (*Core).reconcile,
	"op":            (*Core).op,
}

var errBadRequest = link.Code("bad_request")

// decode parses params strictly: unknown fields are refused.
func decode(params json.RawMessage, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(params)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil || dec.More() {
		return errBadRequest
	}
	return nil
}

// validID accepts a remote id or ref: 1..MaxIDBytes of printable UTF-8.
func validID(s string) bool {
	if len(s) == 0 || len(s) > MaxIDBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// validOpID: the keeper's op ids are UUIDs or writeKey digests.
func validOpID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)
		if !ok {
			return false
		}
	}
	return true
}

func validText(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxTextRunes {
		return false
	}
	return strings.TrimSpace(s) != ""
}

func validEmoji(s string) bool {
	if s == "" || len(s) > MaxEmojiBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r < 0x80 && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func (c *Core) owner(ctx context.Context) (*bridgev2.User, error) {
	return c.o.Bridge.GetUserByMXID(ctx, sink.OwnerMXID)
}

// login returns the linked account's login, or not_logged_in.
func (c *Core) login(ctx context.Context) (*bridgev2.UserLogin, error) {
	user, err := c.owner(ctx)
	if err != nil {
		return nil, err
	}
	ul := user.GetDefaultLogin()
	if ul == nil || ul.Client == nil {
		return nil, link.Code("not_logged_in")
	}
	return ul, nil
}

// outboundCode maps the sink's refusals to protocol codes.
func outboundCode(err error) error {
	switch {
	case errors.Is(err, sink.ErrUnknownConversation):
		return link.Code("unknown_conversation")
	case errors.Is(err, sink.ErrTargetGone):
		return link.Code("target_gone")
	case errors.Is(err, sink.ErrOpMismatch):
		return link.Code("op_mismatch")
	case errors.Is(err, sink.ErrNotLoggedIn):
		return link.Code("not_logged_in")
	}
	return err
}
