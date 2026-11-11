// Package config builds the mautrix-meta configuration the bridge runs with
// (README.md "Forced configuration"): it is forced by our main, never user-editable. Everything goes
// through the egress's bridge listener; reconnect and backfill pacing are
// fixed; typing and presence are never sent. The compartment's floor is
// the belt to these braces: the process has no other route out.
package config

import (
	"fmt"
	"time"

	"maunium.net/go/mautrix/bridgev2/bridgeconfig"

	"go.mau.fi/mautrix-meta/pkg/connector"
)

// Upstream is the mautrix-meta commit go.mod pins.
const Upstream = "da5fbd43c1a6df36f3ea286a068184024ae5d4f6"

// MaxMediaBytes is the per-item media limit (PROTOCOL.md section 6:
// at most 25 MiB). The connector skips larger attachments at arrival and
// media.get refuses them.
const MaxMediaBytes = 25 << 20

// HistoryPage is the size of the first sync per conversation and of each
// older page (PROTOCOL.md section 5.2).
const HistoryPage = 50

// Bridge returns the fixed bridgev2 configuration: the first sync carries
// HistoryPage messages per conversation, and older pages are fetched only
// on demand (the automatic backfill queue stays off; older runs one manual
// task per request).
func Bridge() *bridgeconfig.BridgeConfig {
	perms := bridgeconfig.PermissionLevelUser
	return &bridgeconfig.BridgeConfig{
		CommandPrefix: "!bridge",
		Permissions:   bridgeconfig.PermissionConfig{"*": &perms},
		Backfill: bridgeconfig.BackfillConfig{
			Enabled:            true,
			MaxInitialMessages: HistoryPage,
			MaxCatchupMessages: HistoryPage,
			Queue: bridgeconfig.BackfillQueueConfig{
				Enabled:    false,
				BatchSize:  HistoryPage,
				MaxBatches: -1,
			},
		},
	}
}

// Forced returns the fixed bridge configuration. proxyURL is the egress's
// bridge listener (http://host:port); it is required.
func Forced(proxyURL string) (connector.Config, error) {
	if proxyURL == "" {
		return connector.Config{}, fmt.Errorf("egress proxy URL is required: the bridge must not run without it")
	}
	cfg := connector.Config{
		Proxy:              proxyURL,
		ProxyMedia:         true,
		ProxyE2EE:          true,
		ProxyMessengerLite: true,
		ProxyOther:         true,
		// GetProxyFrom stays empty and Tor stays false (zero values): the
		// proxy address never rotates and never comes from the network.
		MinFullReconnectIntervalSeconds: 3600,
		ForceRefreshIntervalSeconds:     72000,
		CacheConnectionState:            true,
		SendPresenceOnTyping:            false,
		DisplaynameTemplate:             "{{.DisplayName}} (FB)",
		ThreadBackfill:                  connector.ThreadBackfillConfig{BatchCount: 1, BatchDelay: 10 * time.Second},
	}
	if err := cfg.PostProcess(); err != nil {
		return connector.Config{}, fmt.Errorf("config postprocess: %w", err)
	}
	return cfg, nil
}

// Check asserts the invariants of a live configuration (tests, and a sanity
// check at boot).
func Check(cfg connector.Config) error {
	switch {
	case cfg.Proxy == "":
		return fmt.Errorf("proxy is empty")
	case cfg.GetProxyFrom != "":
		return fmt.Errorf("get_proxy_from must stay empty")
	case cfg.Tor:
		return fmt.Errorf("tor must stay false")
	case !cfg.ProxyMedia || !cfg.ProxyE2EE || !cfg.ProxyMessengerLite || !cfg.ProxyOther:
		return fmt.Errorf("all proxy_* flags must be true")
	case cfg.SendPresenceOnTyping:
		return fmt.Errorf("send_presence_on_typing must stay false")
	}
	return nil
}
