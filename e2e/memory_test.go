package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/tzarebczan/eggomi-meta-bridge/config"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/fakenet"
	"github.com/tzarebczan/eggomi-meta-bridge/testing/harness"
)

func selfRSSKiB(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatal("no VmRSS")
	return 0
}

func heapMiB() float64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc) / (1 << 20)
}

// TestMemoryBudget loads 50 conversations of 50 messages (one first sync
// at HistoryPage) and a 25 MiB attachment, and checks the whole test
// process stays well under the compartment's 192 MiB cap.
func TestMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("memory budget run is slow")
	}
	const portals, msgs = 50, config.HistoryPage
	env := harness.New(t, fakenet.New())
	ctx := context.Background()
	login, err := env.Login(ctx, fakenet.LoginID, "Owner")
	if err != nil {
		t.Fatal(err)
	}
	bootRSS, bootHeap := selfRSSKiB(t), heapMiB()

	start := time.Now()
	for p := 0; p < portals; p++ {
		key := networkid.PortalKey{ID: networkid.PortalID(fmt.Sprintf("thread-%d", p)), Receiver: fakenet.LoginID}
		for m := 0; m < msgs; m++ {
			body := fmt.Sprintf("message %d in conversation %d with a representative body of text", m, p)
			login.QueueRemoteEvent(ghostMsg(key, networkid.MessageID(fmt.Sprintf("msg-%d-%d", p, m)), "ghost-1", body, m == 0))
		}
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		n, err := env.Out.Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		items := 0
		if n >= portals*msgs {
			for _, d := range decode(env, 0) {
				if d.Kind == "item" {
					items++
				}
			}
		}
		if items == portals*msgs {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d items journaled", items, portals*msgs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	loadedRSS, loadedHeap := selfRSSKiB(t), heapMiB()

	// A full-size attachment streams to disk: heap does not grow with it.
	blob := io.LimitReader(rand.Reader, config.MaxMediaBytes)
	id, size, err := env.Media.PutReader(blob, config.MaxMediaBytes)
	if err != nil || size != config.MaxMediaBytes {
		t.Fatalf("store: %d %v", size, err)
	}
	chunk, _, err := env.Media.ReadAt(id, size-(32<<10), 32<<10)
	if err != nil || len(chunk) != 32<<10 {
		t.Fatalf("read back: %v", err)
	}
	mediaRSS, mediaHeap := selfRSSKiB(t), heapMiB()

	t.Logf("boot: RSS %.1f MiB heap %.1f MiB", float64(bootRSS)/1024, bootHeap)
	t.Logf("%d items in %s: RSS %.1f MiB heap %.1f MiB", portals*msgs, time.Since(start).Round(time.Millisecond), float64(loadedRSS)/1024, loadedHeap)
	t.Logf("after 25 MiB media: RSS %.1f MiB heap %.1f MiB", float64(mediaRSS)/1024, mediaHeap)
	// The cap is 192 MiB; keep a third spare for messagix's live state.
	if mediaRSS > 128<<10 {
		t.Fatalf("RSS %d KiB over the 128 MiB budget", mediaRSS)
	}
	if mediaHeap-loadedHeap > 8 {
		t.Fatalf("storing a 25 MiB attachment grew the heap by %.1f MiB", mediaHeap-loadedHeap)
	}
}
