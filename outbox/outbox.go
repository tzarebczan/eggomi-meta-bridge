// Package outbox is the bridge's sequenced event journal toward the keeper
// (PROTOCOL.md section 3). Every domain event is appended with a sequence number BEFORE
// it is delivered, so a keeper that disconnects (or a bridge that restarts)
// loses nothing: on reconnect the keeper names its last acknowledged seq and
// the bridge replays everything after it. Rows are deleted when the keeper
// acknowledges them (the keeper commits its records and cursor first, so a
// crash replays at most one batch and never skips one).
//
// Sequence numbers never repeat within one store (AUTOINCREMENT). A wiped
// store starts a new epoch, so a keeper holding a cursor from an older store
// can tell its cursor no longer applies.
package outbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Event is one journal row and one link frame toward the keeper.
type Event struct {
	Seq    int64           `json:"seq"`
	Kind   string          `json:"kind"`
	Portal string          `json:"portal,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// Outbox is the persistent journal.
type Outbox struct {
	db    *sql.DB
	epoch string

	mu      sync.Mutex
	latest  int64
	changed chan struct{} // closed and replaced on every append
}

const schema = `
CREATE TABLE IF NOT EXISTS outbox (
	seq    INTEGER PRIMARY KEY AUTOINCREMENT,
	kind   TEXT NOT NULL,
	portal TEXT NOT NULL DEFAULT '',
	data   BLOB
);
CREATE TABLE IF NOT EXISTS outbox_meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Open creates the journal in an existing database handle.
func Open(db *sql.DB) (*Outbox, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("outbox schema: %w", err)
	}
	o := &Outbox{db: db, changed: make(chan struct{})}
	err := db.QueryRow(`SELECT value FROM outbox_meta WHERE key = 'epoch'`).Scan(&o.epoch)
	if errors.Is(err, sql.ErrNoRows) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		o.epoch = hex.EncodeToString(b[:])
		if _, err := db.Exec(`INSERT INTO outbox_meta (key, value) VALUES ('epoch', ?)`, o.epoch); err != nil {
			return nil, fmt.Errorf("outbox epoch: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("outbox epoch: %w", err)
	}
	// MAX(seq) is 0 once everything is acknowledged; sqlite_sequence keeps
	// the last number handed out, which is what the keeper's cursor holds.
	err = db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'outbox'`).Scan(&o.latest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return o, nil
}

// Epoch identifies this store; it changes only when the store is wiped.
func (o *Outbox) Epoch() string { return o.epoch }

// Append journals one event and wakes every waiter.
func (o *Outbox) Append(kind, portal string, data map[string]any) (Event, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return Event{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	res, err := o.db.Exec(`INSERT INTO outbox (kind, portal, data) VALUES (?, ?, ?)`, kind, portal, raw)
	if err != nil {
		return Event{}, fmt.Errorf("outbox append: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return Event{}, err
	}
	o.latest = seq
	close(o.changed)
	o.changed = make(chan struct{})
	return Event{Seq: seq, Kind: kind, Portal: portal, Data: raw}, nil
}

// Latest returns the newest seq handed out (0 for a new store).
func (o *Outbox) Latest() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.latest
}

// Wait blocks until an event with seq > after exists or ctx ends.
func (o *Outbox) Wait(ctx context.Context, after int64) error {
	for {
		o.mu.Lock()
		latest, ch := o.latest, o.changed
		o.mu.Unlock()
		if latest > after {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Replay returns every journaled event with seq > after, in order.
func (o *Outbox) Replay(after int64) ([]Event, error) {
	return o.Page(after, -1)
}

// Page returns at most limit journaled events with seq > after, in order
// (limit < 0: no limit).
func (o *Outbox) Page(after int64, limit int) ([]Event, error) {
	rows, err := o.db.Query(`SELECT seq, kind, portal, data FROM outbox WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var evt Event
		var data []byte
		if err := rows.Scan(&evt.Seq, &evt.Kind, &evt.Portal, &data); err != nil {
			return nil, err
		}
		evt.Data = data
		out = append(out, evt)
	}
	return out, rows.Err()
}

// Get returns one journaled event, or nil once it is acknowledged.
func (o *Outbox) Get(seq int64) (*Event, error) {
	evts, err := o.Page(seq-1, 1)
	if err != nil || len(evts) == 0 || evts[0].Seq != seq {
		return nil, err
	}
	return &evts[0], nil
}

// Ack deletes every journaled event up to and including seq. The keeper acks
// only after committing its records and cursor in one write.
func (o *Outbox) Ack(seq int64) error {
	_, err := o.db.Exec(`DELETE FROM outbox WHERE seq <= ?`, seq)
	return err
}

// Count returns the number of journaled events not yet acknowledged.
func (o *Outbox) Count(ctx context.Context) (int, error) {
	var n int
	err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&n)
	return n, err
}
