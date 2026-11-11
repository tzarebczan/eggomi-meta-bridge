// Package app assembles the program: its own store (outbox, op table, media
// cache), the sink, and a bridgev2 bridge around a NetworkConnector. The
// binary runs it with the real MetaConnector; tests with fakenet.
package app

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/tzarebczan/eggomi-meta-bridge/config"
	"github.com/tzarebczan/eggomi-meta-bridge/media"
	"github.com/tzarebczan/eggomi-meta-bridge/ops"
	"github.com/tzarebczan/eggomi-meta-bridge/outbox"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
)

// Env is one assembled program.
type Env struct {
	Dir    string
	DB     *sql.DB
	Out    *outbox.Outbox
	Ops    *ops.Table
	Media  *media.Cache
	Sink   *sink.Sink
	Bridge *bridgev2.Bridge
}

// OpenStore opens (or reopens) the program's own SQLite store in dir.
func OpenStore(dir string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(dir, "eggomi.db")+"?_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Start assembles the program in dir and starts the bridge. beforeStart, if
// set, runs after the network connector's Init and before the bridge loads
// existing logins (which connect them): settings the connector must have
// before its first event go there.
func Start(dir string, network bridgev2.NetworkConnector, log zerolog.Logger, beforeStart func(*bridgev2.Bridge) error) (env *Env, err error) {
	env = &Env{Dir: dir}
	if env.DB, err = OpenStore(dir); err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer func() {
		if err != nil {
			env.DB.Close()
		}
	}()
	if env.Out, err = outbox.Open(env.DB); err != nil {
		return nil, err
	}
	if env.Ops, err = ops.Open(env.DB); err != nil {
		return nil, err
	}
	if env.Media, err = media.Open(filepath.Join(dir, "media"), 0); err != nil {
		return nil, err
	}
	env.Sink = sink.New(env.Out, env.Ops, env.Media)

	brDB, err := dbutil.NewFromConfig("meta", dbutil.Config{
		PoolConfig: dbutil.PoolConfig{
			Type:         "sqlite3-fk-wal",
			URI:          "file:" + filepath.Join(dir, "bridge.db") + "?_txlock=immediate",
			MaxOpenConns: 1,
		},
	}, dbutil.ZeroLogger(log))
	if err != nil {
		return nil, fmt.Errorf("open bridge db: %w", err)
	}
	env.Bridge = bridgev2.NewBridge("meta", brDB, log, config.Bridge(), env.Sink, network, commands.NewProcessor)
	if beforeStart != nil {
		if err := beforeStart(env.Bridge); err != nil {
			return nil, err
		}
	}
	if err := env.Bridge.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("start bridge: %w", err)
	}
	// Anything left at the commit point by a previous run is unknown now.
	if err := env.Sink.RecoverOps(context.Background()); err != nil {
		env.Bridge.Stop()
		return nil, fmt.Errorf("recover ops: %w", err)
	}
	return env, nil
}

// Login creates a user login through the network's LoadUserLogin.
func (env *Env) Login(ctx context.Context, loginID networkid.UserLoginID, remoteName string) (*bridgev2.UserLogin, error) {
	user, err := env.Bridge.GetUserByMXID(ctx, sink.OwnerMXID)
	if err != nil {
		return nil, err
	}
	return user.NewLogin(ctx, &database.UserLogin{ID: loginID, RemoteName: remoteName}, nil)
}

// Stop stops the bridge and closes the store.
func (env *Env) Stop(ctx context.Context) {
	env.Bridge.Stop()
	env.DB.Close()
}
