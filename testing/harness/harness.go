// Package harness wires a full in-process bridge for tests (app.Start in a
// temp dir), with any NetworkConnector: fakenet in unit tests, the real
// MetaConnector in hermetic ones.
package harness

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"

	"github.com/tzarebczan/eggomi-meta-bridge/app"
)

// Env is one wired bridge.
type Env = app.Env

// New builds and starts a bridge in a fresh temp dir.
func New(t *testing.T, network bridgev2.NetworkConnector) *Env {
	t.Helper()
	env, err := Start(t.TempDir(), network, zerolog.Nop())
	if err != nil {
		t.Fatalf("start harness: %v", err)
	}
	t.Cleanup(func() { env.Stop(context.Background()) })
	return env
}

// Start assembles the program in dir (restart tests reuse a dir).
func Start(dir string, network bridgev2.NetworkConnector, log zerolog.Logger) (*Env, error) {
	return app.Start(dir, network, log, nil)
}
