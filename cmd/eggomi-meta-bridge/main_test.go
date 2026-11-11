package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"

	"go.mau.fi/mautrix-meta/pkg/metaid"

	"github.com/tzarebczan/eggomi-meta-bridge/config"
	"github.com/tzarebczan/eggomi-meta-bridge/link"
)

// The hermetic test runs this test binary as the bridge: same main, same
// defaults, its own process.
func TestMain(m *testing.M) {
	if os.Getenv("EGGOMI_BRIDGE_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func baseEnv() map[string]string {
	return map[string]string{
		"META_LINK_LISTEN": "10.231.15.20:9380",
		"META_LINK_KEY":    "/run/eggomi-cah/meta.key",
		"META_KEEPER_PUB":  "/run/eggomi-cah/keeper.pub",
		"META_SEALER_PUB":  "/run/eggomi-cah/sealer.pub",
		"META_GENERATION":  "3",
		"META_PROXY":       "http://10.231.16.2:3128",
	}
}

func TestFromEnv(t *testing.T) {
	get := func(env map[string]string) func(string) string { return func(k string) string { return env[k] } }
	s, err := fromEnv(get(baseEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if s.Instance != "meta-bridge" || s.Data != "/data" || s.Generation != 3 || s.Proxy != "http://10.231.16.2:3128" || s.Level != zerolog.InfoLevel {
		t.Fatalf("defaults: %+v", s)
	}
	noSealer := baseEnv()
	delete(noSealer, "META_SEALER_PUB")
	delete(noSealer, "META_GENERATION")
	if s, err := fromEnv(get(noSealer)); err != nil || s.SealerFile != "" {
		t.Fatalf("without a sealer: %+v %v", s, err)
	}
	slash := baseEnv()
	slash["META_PROXY"] = "http://10.231.16.2:3128/"
	if s, err := fromEnv(get(slash)); err != nil || s.Proxy != "http://10.231.16.2:3128" {
		t.Fatalf("trailing slash: %+v %v", s, err)
	}

	bad := []struct{ key, value string }{
		{"META_LINK_LISTEN", ""},
		{"META_LINK_LISTEN", "meta:9380"},
		{"META_LINK_LISTEN", "[::1]:9380"},
		{"META_LINK_LISTEN", "10.0.0.1:0"},
		{"META_LINK_KEY", ""},
		{"META_LINK_KEY", "meta.key"},
		{"META_KEEPER_PUB", "/run/with space"},
		{"META_SEALER_PUB", "sealer.pub"},
		{"META_GENERATION", ""},
		{"META_GENERATION", "0"},
		{"META_GENERATION", "-1"},
		{"META_GENERATION", "x"},
		{"META_INSTANCE", "Meta"},
		{"META_INSTANCE", "meta bridge"},
		{"META_INSTANCE", strings.Repeat("a", 65)},
		{"META_PROXY", ""},
		{"META_PROXY", "https://10.231.16.2:3128"},
		{"META_PROXY", "socks5://10.231.16.2:1080"},
		{"META_PROXY", "http://egress:3128"},
		{"META_PROXY", "http://10.231.16.2"},
		{"META_PROXY", "http://user:pw@10.231.16.2:3128"},
		{"META_PROXY", "http://10.231.16.2:3128/path"},
		{"META_PROXY", "http://10.231.16.2:3128?x=1"},
		{"META_DATA", "data"},
		{"META_LOG", "debug"},
		{"META_LOG", "trace"},
	}
	for _, b := range bad {
		env := baseEnv()
		env[b.key] = b.value
		if _, err := fromEnv(get(env)); err == nil {
			t.Errorf("%s=%q was accepted", b.key, b.value)
		}
	}
}

func TestLoginID(t *testing.T) {
	if got := loginID(map[string]any{"c_user": "100000000000001"}); got != metaid.MakeUserLoginID(100000000000001) {
		t.Fatalf("c_user: %q", got)
	}
	for _, creds := range []map[string]any{{}, {"c_user": ""}, {"c_user": "abc"}, {"c_user": "-5"}, {"c_user": 5}} {
		if got := loginID(creds); got != "" {
			t.Fatalf("%v: %q", creds, got)
		}
	}
}

func TestRunRefusesBadKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", strings.Repeat("ab", 32)+"\n")
	for _, body := range []string{"", strings.Repeat("ab", 31), strings.Repeat("AB", 32), strings.Repeat("zz", 32)} {
		s := &settings{Listen: "127.0.0.1:1", KeyFile: write("bad", body), KeeperFile: good, Proxy: "http://127.0.0.1:1", Data: filepath.Join(dir, "data")}
		if err := run(context.Background(), s, zerolog.Nop()); err == nil || !strings.Contains(err.Error(), "hex") {
			t.Fatalf("key %q: %v", body, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused start touched the volume")
	}
}

// --- hermetic run: the real connector, no network but loopback ---

type vectors struct {
	KK struct {
		KeeperStatic string `json:"keeperStatic"`
		KeeperPublic string `json:"keeperPublic"`
		BridgeStatic string `json:"bridgeStatic"`
		BridgePublic string `json:"bridgePublic"`
	} `json:"kk"`
	Seal struct {
		SealerPublic string `json:"sealerPublic"`
		Variants     struct {
			Fresh []json.RawMessage `json:"fresh"`
		} `json:"variants"`
	} `json:"seal"`
}

// Cookie values the handoff carries (testdata/gen-interop.mjs). c_user is
// the account id, which the bridge may name; these must never be printed,
// answered or left on disk by a failed login.
var canaries = []string{"CANARY-DATR-VALUE", "CANARY-SB-VALUE", "CANARY-XS-VALUE"}

var metaSuffixes = []string{".facebook.com", ".fbcdn.net", ".messenger.com", ".fbsbx.com", ".facebook.net"}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestHermetic boots the bridge with the real MetaConnector in a user and
// network namespace whose only interface is loopback, behind a recording
// proxy that refuses every request, and attempts a cookie login with a
// sealed canary handoff. It checks that every connection asks the proxy,
// only for Meta hosts, that the canary values appear in no log line, no
// answer and no file the failed login leaves, and the process's memory.
func TestHermetic(t *testing.T) {
	if os.Getenv("EGGOMI_HERMETIC") != "1" {
		unshare, err := exec.LookPath("unshare")
		if err == nil {
			err = exec.Command(unshare, "-Urn", "true").Run()
		}
		if err != nil {
			if os.Getenv("EGGOMI_REQUIRE_HERMETIC") == "1" {
				t.Fatalf("unshare -Urn unavailable: %v", err)
			}
			t.Skipf("needs unshare -Urn (user and network namespaces): %v", err)
		}
		cmd := exec.Command(unshare, "-Urn", os.Args[0], "-test.run=^TestHermetic$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "EGGOMI_HERMETIC=1")
		out, err := cmd.CombinedOutput()
		t.Logf("namespace run:\n%s", out)
		if err != nil || !bytes.Contains(out, []byte("--- PASS: TestHermetic")) {
			t.Fatalf("hermetic run failed: %v", err)
		}
		return
	}
	hermeticChild(t)
}

func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var req struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
		_     [22]byte
	}
	copy(req.name[:], "lo")
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	req.flags |= unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	return nil
}

type proxyLog struct {
	mu    sync.Mutex
	lines []string // "METHOD host"
}

func (p *proxyLog) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

func rssKiB(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			return strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
		}
	}
	return 0, errors.New("no VmRSS")
}

func hermeticChild(t *testing.T) {
	if err := bringLoopbackUp(); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Name != "lo" {
			t.Fatalf("not hermetic: interface %s present", i.Name)
		}
	}

	raw, err := os.ReadFile("../../testdata/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	plog := &proxyLog{}
	pln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if r.Method != http.MethodConnect {
			host = r.URL.Host
		}
		plog.mu.Lock()
		plog.lines = append(plog.lines, r.Method+" "+host)
		plog.mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	})}
	go proxy.Serve(pln)
	defer proxy.Close()

	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{"meta.key": v.KK.BridgeStatic, "keeper.pub": v.KK.KeeperPublic, "sealer.pub": v.Seal.SealerPublic} {
		if err := os.WriteFile(filepath.Join(keys, name), []byte(val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := lln.Addr().String()
	lln.Close()

	stderr, stdout := &syncBuffer{}, &syncBuffer{}
	bridge := exec.Command(os.Args[0])
	bridge.Env = []string{
		"EGGOMI_BRIDGE_MAIN=1",
		"HOME=" + dir,
		"META_LINK_LISTEN=" + listen,
		"META_LINK_KEY=" + filepath.Join(keys, "meta.key"),
		"META_KEEPER_PUB=" + filepath.Join(keys, "keeper.pub"),
		"META_SEALER_PUB=" + filepath.Join(keys, "sealer.pub"),
		"META_GENERATION=1",
		"META_PROXY=http://" + pln.Addr().String(),
		"META_DATA=" + data,
	}
	bridge.Stdout, bridge.Stderr = stdout, stderr
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- bridge.Wait() }()
	defer func() {
		bridge.Process.Kill()
		<-exited
	}()

	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stderr.String(), `"message":"ready"`) {
		if time.Now().After(deadline) {
			t.Fatalf("bridge never became ready:\n%s", stderr.String())
		}
		select {
		case err := <-exited:
			t.Fatalf("bridge exited: %v\n%s", err, stderr.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	bootRSS, _ := rssKiB(bridge.Process.Pid)

	frames := &syncBuffer{}
	c, err := link.Dial(listen, unhex(v.KK.KeeperStatic), unhex(v.KK.BridgePublic))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	call := func(method string, params any) (map[string]any, string) {
		var res map[string]any
		err := c.Call(method, params, &res)
		b, _ := json.Marshal(res)
		frames.Write(b)
		var re *link.RemoteError
		if errors.As(err, &re) {
			frames.Write([]byte(re.Code))
			return nil, re.Code
		} else if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		return res, ""
	}

	st, code := call("status", map[string]any{})
	if code != "" || st["upstream"] != config.Upstream || st["login"] != nil {
		t.Fatalf("status: %v %s", st, code)
	}
	if lines := plog.all(); len(lines) != 0 {
		t.Fatalf("the bridge connected out before any login: %v", lines)
	}

	start := time.Now()
	_, code = call("login.cookies", map[string]any{"sealed": v.Seal.Variants.Fresh[0]})
	took := time.Since(start)
	switch {
	case code == "":
		t.Fatalf("a login through a refusing proxy succeeded")
	case code == "bad_request" || code == "not_configured" || strings.HasPrefix(code, "denied_"):
		t.Fatalf("the handoff was refused before the network: %s", code)
	}
	t.Logf("login answer %q after %s", code, took.Round(time.Millisecond))

	var loginEvt map[string]any
	res, _ := call("events.next", map[string]any{"after": 0, "waitMs": 2000})
	evts, _ := res["events"].([]any)
	for _, e := range evts {
		if m, _ := e.(map[string]any); m["kind"] == "login" {
			loginEvt, _ = m["data"].(map[string]any)
		}
	}
	if loginEvt["state"] != "failed" || loginEvt["code"] != code {
		t.Fatalf("login event: %v", evts)
	}

	lines := plog.all()
	if len(lines) == 0 {
		t.Fatalf("the login reached nothing through the proxy")
	}
	for _, l := range lines {
		method, hostport, _ := strings.Cut(l, " ")
		host, _, err := net.SplitHostPort(hostport)
		if err != nil {
			host = hostport
		}
		meta := false
		for _, s := range metaSuffixes {
			meta = meta || strings.HasSuffix("."+host, s)
		}
		if method != http.MethodConnect || !meta {
			t.Fatalf("proxy request outside the Meta hosts or not tunnelled: %s", l)
		}
	}
	t.Logf("proxy saw %d requests: %v", len(lines), lines)

	loginRSS, err := rssKiB(bridge.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bridge RSS: boot %.1f MiB, after login attempt %.1f MiB", float64(bootRSS)/1024, float64(loginRSS)/1024)
	// The compartment's cap is 192 MiB; keep a third of it spare.
	if loginRSS > 128<<10 {
		t.Fatalf("RSS %d KiB over the 128 MiB budget", loginRSS)
	}

	c.Close()
	bridge.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("bridge exit on SIGTERM: %v\n%s", err, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("bridge did not stop on SIGTERM")
	}
	exited <- nil // for the deferred Kill

	scan := map[string]string{"stderr": stderr.String(), "stdout": stdout.String(), "frames": frames.String()}
	filepath.WalkDir(data, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			scan[p] = string(b)
		}
		return nil
	})
	if len(scan) < 5 {
		t.Fatalf("the data dir holds fewer files than expected: %d", len(scan)-3)
	}
	for where, text := range scan {
		for _, c := range canaries {
			if strings.Contains(text, c) {
				t.Fatalf("canary %s found in %s", c, where)
			}
		}
	}
}
