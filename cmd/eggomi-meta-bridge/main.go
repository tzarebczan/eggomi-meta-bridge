// Command eggomi-meta-bridge runs mautrix-meta's Messenger connector with
// the Eggomi sink in place of a Matrix homeserver, and answers the keeper
// over a Noise KK link (PROTOCOL.md). It is the only process in its
// compartment; its only way out is the egress proxy.
//
// Environment (paths are absolute; keys are 64 lowercase hex in a file):
//
//	META_LINK_LISTEN  <ipv4>:<port>                 the keeper's link listener (9380)
//	META_LINK_KEY     /run/eggomi-cah/meta.key      this compartment's static private key
//	META_KEEPER_PUB   /run/eggomi-cah/keeper.pub    the keeper's static public key; a cookie
//	                                                handoff's audience is its hex
//	META_SEALER_PUB   /run/eggomi-cah/sealer.pub    the guard's sealing key; unset, login.cookies
//	                                                answers not_configured
//	META_INSTANCE     meta-bridge                   the recipient_instance a handoff must name
//	META_GENERATION   (required with the sealer)    the recipient_generation a handoff must name
//	META_PROXY        http://<ipv4>:<port>          the egress's bridge listener (required)
//	META_DATA         /data                         the volume: bridge.db, eggomi.db, media/
//	META_LOG          info                          info | warn | error
//
// GOMEMLIMIT, when unset, defaults to DefaultMemoryLimit.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-meta/pkg/connector"
	"go.mau.fi/mautrix-meta/pkg/metaid"

	"github.com/tzarebczan/eggomi-meta-bridge/app"
	"github.com/tzarebczan/eggomi-meta-bridge/config"
	"github.com/tzarebczan/eggomi-meta-bridge/core"
	"github.com/tzarebczan/eggomi-meta-bridge/link"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

// DefaultMemoryLimit is the Go runtime's soft limit, under the
// compartment's 192 MiB cap.
const DefaultMemoryLimit = 160 << 20

type settings struct {
	Listen     string
	KeyFile    string
	KeeperFile string
	SealerFile string
	Instance   string
	Generation int64
	Proxy      string
	Data       string
	Level      zerolog.Level
}

func abs(v, name string) (string, error) {
	if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\x00 \t\r\n") {
		return "", fmt.Errorf("%s must be an absolute path", name)
	}
	return v, nil
}

func ipv4Port(v string) bool {
	ap, err := netip.ParseAddrPort(v)
	return err == nil && ap.Addr().Is4() && ap.Port() != 0
}

// fromEnv reads and checks the settings; any doubt refuses to start.
func fromEnv(getenv func(string) string) (*settings, error) {
	s := &settings{Instance: "meta-bridge", Data: "/data", Level: zerolog.InfoLevel}
	var err error
	if s.Listen = getenv("META_LINK_LISTEN"); !ipv4Port(s.Listen) {
		return nil, errors.New("META_LINK_LISTEN must be <ipv4>:<port>")
	}
	if s.KeyFile, err = abs(getenv("META_LINK_KEY"), "META_LINK_KEY"); err != nil {
		return nil, err
	}
	if s.KeeperFile, err = abs(getenv("META_KEEPER_PUB"), "META_KEEPER_PUB"); err != nil {
		return nil, err
	}
	if v := getenv("META_SEALER_PUB"); v != "" {
		if s.SealerFile, err = abs(v, "META_SEALER_PUB"); err != nil {
			return nil, err
		}
		gen, err := strconv.ParseInt(getenv("META_GENERATION"), 10, 64)
		if err != nil || gen < 1 {
			return nil, errors.New("META_GENERATION must be a positive integer when META_SEALER_PUB is set")
		}
		s.Generation = gen
	}
	if v := getenv("META_INSTANCE"); v != "" {
		s.Instance = v
	}
	if len(s.Instance) > 64 || strings.Trim(s.Instance, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return nil, errors.New("META_INSTANCE must be 1-64 of [a-z0-9-]")
	}
	u, err := url.Parse(getenv("META_PROXY"))
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || !ipv4Port(u.Host) {
		// The compartment resolves no names: the egress is an address.
		return nil, errors.New("META_PROXY must be http://<ipv4>:<port>")
	}
	s.Proxy = "http://" + u.Host
	if v := getenv("META_DATA"); v != "" {
		if s.Data, err = abs(v, "META_DATA"); err != nil {
			return nil, err
		}
	}
	switch getenv("META_LOG") {
	case "", "info":
	case "warn":
		s.Level = zerolog.WarnLevel
	case "error":
		s.Level = zerolog.ErrorLevel
	default:
		// debug and trace print what upstream logs at those levels; never here.
		return nil, errors.New("META_LOG must be info, warn or error")
	}
	return s, nil
}

func readKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	text := strings.TrimSpace(string(data))
	key, err := hex.DecodeString(text)
	if err != nil || len(key) != 32 || text != strings.ToLower(text) {
		return nil, fmt.Errorf("%s: not 64 lowercase hex", path)
	}
	return key, nil
}

// loginID is the login a cookie set belongs to: c_user, the account's id.
func loginID(creds map[string]any) networkid.UserLoginID {
	s, _ := creds["c_user"].(string)
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return ""
	}
	return metaid.MakeUserLoginID(id)
}

func run(ctx context.Context, s *settings, log zerolog.Logger) error {
	priv, err := readKey(s.KeyFile)
	if err != nil {
		return err
	}
	keeper, err := readKey(s.KeeperFile)
	if err != nil {
		return err
	}
	seal := core.SealConfig{BridgePrivate: priv, Audience: hex.EncodeToString(keeper), Instance: s.Instance, Generation: s.Generation}
	if s.SealerFile != "" {
		if seal.SealerPublic, err = readKey(s.SealerFile); err != nil {
			return err
		}
	}
	mcfg, err := config.Forced(s.Proxy)
	if err != nil {
		return err
	}
	if err := config.Check(mcfg); err != nil {
		return fmt.Errorf("forced config: %w", err)
	}
	if err := os.MkdirAll(s.Data, 0o700); err != nil {
		return err
	}
	mc := &connector.MetaConnector{Config: mcfg}
	env, err := app.Start(s.Data, mc, log, func(*bridgev2.Bridge) error {
		// Media is fetched when the keeper asks (media.get), never at arrival,
		// and nothing larger than the limit is fetched at all.
		mc.SetUseDirectMedia()
		mc.SetMaxFileSize(config.MaxMediaBytes)
		return nil
	})
	if err != nil {
		return err
	}
	defer env.Stop(context.Background())
	handler, err := core.New(core.Options{
		Bridge: env.Bridge, Sink: env.Sink, Out: env.Out, Ops: env.Ops, Media: env.Media, DB: env.DB,
		Login: func(ctx context.Context, user *bridgev2.User, creds map[string]any) error {
			return mc.CreateUserLoginFromCredentials(ctx, user, creds)
		},
		LoginID:  loginID,
		Download: mc.Download,
		MaxMedia: config.MaxMediaBytes,
		Seal:     seal,
		Log:      log,
		Version:  version,
		Upstream: config.Upstream,
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", s.Listen)
	if err != nil {
		return err
	}
	srv := &link.Server{StaticPrivate: priv, KeeperPublic: keeper, Handler: handler, Log: log}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info().Str("listen", ln.Addr().String()).Str("version", version).Str("upstream", config.Upstream).
		Bool("handoff", seal.SealerPublic != nil).Msg("ready")
	select {
	case <-ctx.Done():
		srv.Close()
		log.Info().Msg("stopping")
		return nil
	case err := <-served:
		srv.Close()
		return fmt.Errorf("link listener: %w", err)
	}
}

func newLogger(w io.Writer, level zerolog.Level) zerolog.Logger {
	return zerolog.New(w).Level(level).With().Timestamp().Logger()
}

func main() {
	s, err := fromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "eggomi-meta-bridge:", err)
		os.Exit(2)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(DefaultMemoryLimit)
	}
	log := newLogger(os.Stderr, s.Level)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, s, log); err != nil {
		log.Error().Err(err).Msg("exit")
		stop()
		os.Exit(1)
	}
}
