// Package ops is the bridge's persistent outbound operation table. It holds
// the commit point (PROTOCOL.md section 5.1): an operation is recorded here BEFORE
// the message is handed to the network connector, so a crash after Begin and
// before Settle means "unknown" (maybe sent), never "rejected" and never
// silently resent. Rows survive restarts; on boot the core marks every row
// still in state "committed" as "unknown".
package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// State of one outbound operation.
const (
	StateCommitted = "committed" // recorded, not yet settled by the network
	StateAccepted  = "accepted"  // the network confirmed, remote id known
	StateRejected  = "rejected"  // provably not sent (certain failure)
	StateUnknown   = "unknown"   // crash, timeout or lost link after the commit point; never retried
)

// ErrDuplicate is returned by Begin when the op id already exists with the
// same payload. The link layer answers with the stored row instead of
// sending again.
var ErrDuplicate = errors.New("duplicate op id")

// ErrMismatch is returned by Begin when the op id already exists with a
// different payload (op_mismatch). Nothing is sent.
var ErrMismatch = errors.New("op_mismatch")

// Op is one row of the table.
type Op struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // send | react | unreact | redact
	Conversation string `json:"conversation,omitempty"`
	State        string `json:"state"`
	RemoteID     string `json:"remoteId,omitempty"`
	Code         string `json:"code,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
	SettledAt    int64  `json:"settledAt,omitempty"`
}

// Table is the persistent operation table.
type Table struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS ops (
	op_id        TEXT PRIMARY KEY,
	kind         TEXT NOT NULL,
	conversation TEXT NOT NULL DEFAULT '',
	state        TEXT NOT NULL,
	remote_id    TEXT NOT NULL DEFAULT '',
	code         TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	settled_at   INTEGER NOT NULL DEFAULT 0,
	digest       TEXT NOT NULL DEFAULT ''
);
`

// Open creates the table in an existing database handle.
func Open(db *sql.DB) (*Table, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("ops schema: %w", err)
	}
	return &Table{db: db}, nil
}

// Begin records the commit point. It must run before the message is handed to
// the network connector. digest binds the op id to its payload. A repeated
// op id is refused either way (nothing is re-sent): ErrDuplicate for the
// same payload, ErrMismatch for another.
func (t *Table) Begin(ctx context.Context, opID, kind, conversation, digest string) error {
	res, err := t.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO ops (op_id, kind, conversation, state, created_at, digest) VALUES (?, ?, ?, ?, ?, ?)`,
		opID, kind, conversation, StateCommitted, time.Now().UnixMilli(), digest)
	if err != nil {
		return fmt.Errorf("ops begin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var stored string
	if err := t.db.QueryRowContext(ctx, `SELECT digest FROM ops WHERE op_id = ?`, opID).Scan(&stored); err != nil {
		return fmt.Errorf("ops begin: %w", err)
	}
	if stored != digest {
		return ErrMismatch
	}
	return ErrDuplicate
}

// Settle moves a committed operation to its final state. Settling an already
// settled row is a no-op (the first settle wins).
func (t *Table) Settle(ctx context.Context, opID, state, remoteID, code string) (bool, error) {
	res, err := t.db.ExecContext(ctx,
		`UPDATE ops SET state = ?, remote_id = ?, code = ?, settled_at = ? WHERE op_id = ? AND state = ?`,
		state, remoteID, code, time.Now().UnixMilli(), opID, StateCommitted)
	if err != nil {
		return false, fmt.Errorf("ops settle: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Get returns the stored row, or nil if the op id is unknown.
func (t *Table) Get(ctx context.Context, opID string) (*Op, error) {
	row := t.db.QueryRowContext(ctx,
		`SELECT op_id, kind, conversation, state, remote_id, code, created_at, settled_at FROM ops WHERE op_id = ?`, opID)
	return scan(row)
}

// Committed returns every row still at the commit point (used at boot).
func (t *Table) Committed(ctx context.Context) ([]Op, error) {
	rows, err := t.db.QueryContext(ctx,
		`SELECT op_id, kind, conversation, state, remote_id, code, created_at, settled_at FROM ops WHERE state = ?`, StateCommitted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Op
	for rows.Next() {
		op, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *op)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(row scanner) (*Op, error) {
	var op Op
	if err := row.Scan(&op.ID, &op.Kind, &op.Conversation, &op.State, &op.RemoteID, &op.Code, &op.CreatedAt, &op.SettledAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &op, nil
}

// MarshalData renders the op event payload the keeper receives.
func (op *Op) MarshalData() json.RawMessage {
	data, _ := json.Marshal(map[string]any{
		"opId":     op.ID,
		"state":    op.State,
		"remoteId": op.RemoteID,
		"code":     op.Code,
	})
	return data
}
