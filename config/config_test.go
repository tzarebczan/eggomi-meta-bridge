package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.mau.fi/mautrix-meta/pkg/connector"
	"go.mau.fi/mautrix-meta/pkg/messagix/useragent"
)

func TestForcedRequiresProxy(t *testing.T) {
	if _, err := Forced(""); err == nil {
		t.Fatal("an empty proxy was accepted")
	}
}

func TestForcedHoldsInvariants(t *testing.T) {
	cfg, err := Forced("http://10.231.16.2:3128")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy != "http://10.231.16.2:3128" || cfg.MinFullReconnectIntervalSeconds != 3600 || cfg.ForceRefreshIntervalSeconds != 72000 {
		t.Fatalf("forced values: %+v", cfg)
	}
	breaks := map[string]func(*connector.Config){
		"proxy":          func(c *connector.Config) { c.Proxy = "" },
		"get_proxy_from": func(c *connector.Config) { c.GetProxyFrom = "http://example.invalid/proxy" },
		"tor":            func(c *connector.Config) { c.Tor = true },
		"proxy_media":    func(c *connector.Config) { c.ProxyMedia = false },
		"proxy_e2ee":     func(c *connector.Config) { c.ProxyE2EE = false },
		"proxy_lite":     func(c *connector.Config) { c.ProxyMessengerLite = false },
		"proxy_other":    func(c *connector.Config) { c.ProxyOther = false },
		"typing":         func(c *connector.Config) { c.SendPresenceOnTyping = true },
	}
	for name, mutate := range breaks {
		c := cfg
		mutate(&c)
		if Check(c) == nil {
			t.Errorf("Check accepted a config with %s changed", name)
		}
	}
}

func TestBridgeBackfill(t *testing.T) {
	b := Bridge()
	if !b.Backfill.Enabled || b.Backfill.MaxInitialMessages != HistoryPage || b.Backfill.MaxCatchupMessages != HistoryPage {
		t.Fatalf("first sync: %+v", b.Backfill)
	}
	// Older pages run only when the keeper asks: the automatic queue stays off.
	if b.Backfill.Queue.Enabled || b.Backfill.Queue.BatchSize != HistoryPage {
		t.Fatalf("queue: %+v", b.Backfill.Queue)
	}
}

// The status answer names Upstream as the source of what runs; it must be
// the commit go.mod pins.
func TestUpstreamMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*go\.mau\.fi/mautrix-meta v\S+-([0-9a-f]{12})$`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod does not pin go.mau.fi/mautrix-meta by commit")
	}
	if !strings.HasPrefix(Upstream, string(m[1])) || len(Upstream) != 40 {
		t.Fatalf("config.Upstream is %s, go.mod pins %s", Upstream, m[1])
	}
}

// Upstream's web user agent claims a fixed Chrome version, which ages into
// a fingerprint the owner's browser does not share. A new pin that changes
// it fails here so the change gets reviewed. EGGOMI_BROWSER_CHROME, the
// major version of the owner's browser, turns the drift report into a check.
func TestUserAgentDrift(t *testing.T) {
	const pinned = "141"
	if useragent.ChromeVersion != pinned {
		t.Fatalf("upstream's user agent now claims Chrome %s (was %s): review it, then update this test", useragent.ChromeVersion, pinned)
	}
	if !strings.Contains(useragent.UserAgent, "Chrome/"+useragent.ChromeVersion+".") || !strings.Contains(useragent.SecCHUserAgent, `v="`+useragent.ChromeVersion+`"`) {
		t.Fatalf("user agent strings do not follow ChromeVersion")
	}
	want := os.Getenv("EGGOMI_BROWSER_CHROME")
	if want == "" {
		t.Logf("user agent claims Chrome %s; set EGGOMI_BROWSER_CHROME to check drift", useragent.ChromeVersion)
		return
	}
	browser, err := strconv.Atoi(want)
	if err != nil {
		t.Fatalf("EGGOMI_BROWSER_CHROME=%q is not a major version", want)
	}
	have, _ := strconv.Atoi(useragent.ChromeVersion)
	if d := browser - have; d > 1 || d < -1 {
		t.Errorf("user-agent drift: bridge claims Chrome %d, the browser is %d", have, browser)
	}
}
