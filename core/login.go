package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"go.mau.fi/mautrix-meta/pkg/messagix/httpclient"
	"go.mau.fi/mautrix-meta/pkg/messagix/loginerrors"

	"github.com/tzarebczan/eggomi-meta-bridge/link"
	"github.com/tzarebczan/eggomi-meta-bridge/seal"
)

// Handoff rules for login.cookies (PROTOCOL.md section 7.1). The keeper and the guard
// enforce them first; the bridge refuses on its own too.
const (
	// HandoffOrigin and HandoffField are the only cookie source accepted.
	HandoffOrigin = "https://www.facebook.com"
	HandoffField  = "cookies"
	// MaxHandoffsPerDay counts opened handoffs in a rolling 24 hours.
	MaxHandoffsPerDay = 4
)

func (c *Core) sealConfigured() bool {
	s := c.o.Seal
	return len(s.BridgePrivate) == 32 && len(s.SealerPublic) == 32 && s.Audience != "" && s.Instance != "" && s.Generation > 0
}

// boundOK checks the fields a cookie handoff must be bound to. Everything
// else in the bound set is the guard's business.
func (c *Core) boundOK(b seal.Bound) bool {
	num, ok := b["recipient_generation"].(json.Number)
	if !ok {
		return false
	}
	gen, err := num.Int64()
	return err == nil &&
		gen == c.o.Seal.Generation &&
		b.Str("field") == HandoffField &&
		b.Str("origin") == HandoffOrigin &&
		b.Str("audience") == c.o.Seal.Audience &&
		b.Str("recipient_instance") == c.o.Seal.Instance
}

func (c *Core) handoffsToday(ctx context.Context) (int, error) {
	var n int
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	err := c.o.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM used_grants WHERE used_at > ?`, since).Scan(&n)
	return n, err
}

// spendGrant records a grant as used; a second use is a replay.
func (c *Core) spendGrant(ctx context.Context, grantRef string) error {
	sum := sha256.Sum256([]byte(grantRef))
	res, err := c.o.DB.ExecContext(ctx, `INSERT OR IGNORE INTO used_grants (grant_hash, used_at) VALUES (?, ?)`,
		hex.EncodeToString(sum[:]), time.Now().UnixMilli())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return link.Code("denied_replay")
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// loginCode classifies a login failure. The messagix error text never leaves.
func loginCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, loginerrors.Checkpoint), errors.Is(err, httpclient.ErrCheckpointRequired):
		return "checkpoint"
	case errors.Is(err, loginerrors.Challenge), errors.Is(err, httpclient.ErrChallengeRequired):
		return "challenge"
	case errors.Is(err, loginerrors.Consent), errors.Is(err, httpclient.ErrConsentRequired):
		return "consent"
	case errors.Is(err, loginerrors.TokenInvalidated), errors.Is(err, httpclient.ErrTokenInvalidated):
		return "token_invalidated"
	case errors.Is(err, loginerrors.RateLimited), errors.Is(err, httpclient.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, loginerrors.AccountSuspended), errors.Is(err, httpclient.ErrAccountSuspended):
		return "account_suspended"
	case errors.Is(err, loginerrors.MissingCookies):
		return "denied_payload"
	case strings.Contains(err.Error(), "does not match"):
		return "account_mismatch"
	}
	return "login_failed"
}

func (c *Core) emitLogin(data map[string]any) {
	if _, err := c.o.Out.Append("login", "", data); err != nil {
		c.o.Log.Error().Err(err).Msg("outbox append failed")
	}
}

// loginCookies opens a sealed cookie handoff and links the account (plan
// §4.1 step 5). Fail closed: any doubt about the blob refuses it before the
// network is touched; the plaintext is zeroed as soon as it is parsed.
func (c *Core) loginCookies(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Sealed *seal.Blob `json:"sealed"`
	}
	if err := decode(params, &p); err != nil || p.Sealed == nil {
		return nil, errBadRequest
	}
	if !c.loginMu.TryLock() {
		return nil, link.Code("busy")
	}
	defer c.loginMu.Unlock()
	if !c.sealConfigured() || c.o.Login == nil {
		return nil, link.Code("not_configured")
	}
	if n, err := c.handoffsToday(ctx); err != nil {
		return nil, err
	} else if n >= MaxHandoffsPerDay {
		return nil, link.Code("handoff_limit")
	}
	plaintext, bound, err := seal.Open(c.o.Seal.BridgePrivate, c.o.Seal.SealerPublic, p.Sealed)
	if err != nil {
		var se *seal.Error
		if errors.As(err, &se) {
			return nil, link.Code(se.Code)
		}
		return nil, link.Code("denied_seal")
	}
	defer zero(plaintext)
	if !c.boundOK(bound) {
		return nil, link.Code("denied_bound")
	}
	if err := c.spendGrant(ctx, bound.Str("grant_ref")); err != nil {
		return nil, err
	}
	creds, err := seal.Cookies(plaintext)
	zero(plaintext)
	if err != nil {
		return nil, link.Code("denied_payload")
	}
	defer clear(creds)

	user, err := c.owner(ctx)
	if err != nil {
		return nil, err
	}
	if existing := user.GetDefaultLogin(); existing != nil && c.o.LoginID != nil && existing.ID != c.o.LoginID(creds) {
		return nil, link.Code("account_mismatch")
	}
	// A login that started finishes even if the keeper's connection drops:
	// the grant is spent either way.
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), LoginTimeout)
	defer cancel()
	lctx = c.o.Log.With().Str("component", "login").Logger().WithContext(lctx)
	if err := c.o.Login(lctx, user, creds); err != nil {
		code := loginCode(err)
		c.o.Log.Warn().Str("code", code).Msg("login failed")
		c.emitLogin(map[string]any{"state": "failed", "code": code})
		return nil, link.Code(code)
	}
	info := &loginInfo{}
	if ul := user.GetDefaultLogin(); ul != nil {
		info.ID, info.Name = string(ul.ID), ul.RemoteName
	}
	c.emitLogin(map[string]any{"state": "linked", "id": info.ID, "name": info.Name})
	return map[string]any{"ok": true, "login": info}, nil
}

// loginSecret is the Messenger PIN for encrypted history (PROTOCOL.md section 7.2). The
// pinned mautrix-meta has no restore flow to give it to, so the blob is
// refused without being opened: the PIN never exists in this process.
func (c *Core) loginSecret(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Sealed *seal.Blob `json:"sealed"`
	}
	if err := decode(params, &p); err != nil || p.Sealed == nil {
		return nil, errBadRequest
	}
	return nil, link.Code("unsupported")
}

// logout signs the bridge's session out at Meta (removing its encrypted-chat
// device) and deletes the login. Wiping the volume is the compartment's job.
func (c *Core) logout(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct{}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if !c.loginMu.TryLock() {
		return nil, link.Code("busy")
	}
	defer c.loginMu.Unlock()
	user, err := c.owner(ctx)
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), LoginTimeout)
	defer cancel()
	logins := user.GetUserLogins()
	for _, ul := range logins {
		ul.Logout(lctx)
	}
	c.emitLogin(map[string]any{"state": "logged_out"})
	return map[string]any{"ok": true, "count": len(logins)}, nil
}
