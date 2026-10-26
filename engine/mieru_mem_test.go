package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	apiclient "github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/enfein/mieru/v3/pkg/replay"
	"google.golang.org/protobuf/proto"

	"github.com/W1nCwC/W1nCray-prism/gate"
	prismmieru "github.com/W1nCwC/W1nCray-prism/inbound/mieru"
)

// Measurement only: skipped unless MIERU_MEM=1.
//
//	MIERU_TIERS=500,2000,5000  cumulative session counts of phases A and C
//	MIERU_LONG=200 / MIERU_LONG_SECS=30  phase B concurrency / duration
//	MIERU_REPLAY=0  skip the replay-cache fill (it allocates a few hundred MB)
//
// The client and the server share this process, so every number includes both.

type memSample struct{ heapAlloc, heapInuse, sys, rss uint64 }

func rssBytes() uint64 {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			return 0
		}
		f := strings.Fields(string(b))
		if len(f) < 2 {
			return 0
		}
		n, _ := strconv.ParseUint(f[1], 10, 64)

		return n * uint64(os.Getpagesize())
	case "windows":
		out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(os.Getpid()), "/FO", "CSV", "/NH").Output()
		if err != nil {
			return 0
		}
		cols := strings.Split(strings.TrimSpace(string(out)), "\",\"")
		if len(cols) < 5 {
			return 0
		}
		var digits strings.Builder
		for _, r := range cols[4] {
			if r >= '0' && r <= '9' {
				digits.WriteRune(r)
			}
		}
		n, _ := strconv.ParseUint(digits.String(), 10, 64)

		return n * 1024 // working set, KiB
	}

	return 0
}

func takeMem(gc, withRSS bool) memSample {
	if gc {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := memSample{heapAlloc: m.HeapAlloc, heapInuse: m.HeapInuse, sys: m.Sys}
	if withRSS {
		s.rss = rssBytes()
	}

	return s
}

func mb(v uint64) string { return fmt.Sprintf("%.1f", float64(v)/1048576) }

func dmb(a, b uint64) string { return fmt.Sprintf("%+.1f", (float64(a)-float64(b))/1048576) }

func memClient(port int, udp bool) (apiclient.Client, error) {
	transport := appctlpb.TransportProtocol_TCP
	if udp {
		transport = appctlpb.TransportProtocol_UDP
	}
	profile := &appctlpb.ClientProfile{
		ProfileName: proto.String("m"),
		User:        &appctlpb.User{Name: proto.String("1001"), Password: proto.String(uuidA)},
		Servers: []*appctlpb.ServerEndpoint{{
			IpAddress:    proto.String("127.0.0.1"),
			PortBindings: []*appctlpb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: transport.Enum()}},
		}},
	}
	c := apiclient.NewClient()
	if err := c.Store(&apiclient.ClientConfig{Profile: profile}); err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}

	return c, nil
}

func memFetch(c apiclient.Client, target string, n int, slow time.Duration, timeout time.Duration) error {
	host := strings.TrimPrefix(target, "https://")
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var s model.NetAddrSpec
		if err := s.AddrSpec.From(host); err != nil {
			return nil, err
		}
		s.Net = "tcp"
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		return c.DialContext(ctx, s)
	}
	tr := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout}
	resp, err := cl.Get(fmt.Sprintf("%s/bytes?n=%d&slow=%d", target, n, slow.Milliseconds()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	got, err := io.Copy(io.Discard, resp.Body)
	if err == nil && got != int64(n) {
		err = fmt.Errorf("short body %d/%d", got, n)
	}

	return err
}

func memTiers(t *testing.T, def []int) []int {
	s := os.Getenv("MIERU_TIERS")
	if s == "" {
		return def
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			t.Fatalf("MIERU_TIERS: %v", err)
		}
		out = append(out, n)
	}

	return out
}

func memSetup(t *testing.T, transport string) (*env, int) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(mieruInbound("in", port, transport, ""))); err != nil {
		t.Fatalf("apply: %v", err)
	}
	v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})

	return v, port
}

// phaseA opens cumulative fresh client sessions (one handshake each) and
// fetches 1 KiB through each, reporting memory after every tier.
func phaseA(t *testing.T, transport string, tiers []int) {
	udp := transport == "udp"
	v, port := memSetup(t, transport)
	// warm-up so one-time allocations are in the baseline
	for i := 0; i < 5; i++ {
		c, err := memClient(port, udp)
		if err != nil {
			t.Fatal(err)
		}
		_ = memFetch(c, v.target.URL, 1024, 0, 20*time.Second)
		_ = c.Stop()
	}
	time.Sleep(time.Second)
	base := takeMem(true, true)
	t.Logf("[%s] baseline HeapAlloc=%sMB HeapInuse=%sMB Sys=%sMB RSS=%sMB", transport, mb(base.heapAlloc), mb(base.heapInuse), mb(base.sys), mb(base.rss))
	done, fails := 0, 0
	start := time.Now()
	// Client Stop() blocks ~1.7s on TCP (graceful close), so it runs
	// asynchronously; every tier waits for all of them before measuring.
	var stops sync.WaitGroup
	for _, tier := range tiers {
		for ; done < tier; done++ {
			c, err := memClient(port, udp)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			if err := memFetch(c, v.target.URL, 1024, 0, 20*time.Second); err != nil {
				fails++
				if fails <= 3 {
					t.Logf("[%s] fetch %d: %v", transport, done, err)
				}
			}
			stops.Add(1)
			go func() {
				defer stops.Done()
				_ = c.Stop()
			}()
		}
		stops.Wait()
		time.Sleep(2 * time.Second)
		s := takeMem(true, true)
		t.Logf("[%s] N=%d fails=%d elapsed=%s | HeapAlloc=%sMB (%sMB) HeapInuse=%sMB (%sMB) Sys=%sMB (%sMB) RSS=%sMB (%sMB) | per-session HeapInuse=%.1fKB Sys=%.1fKB goroutines=%d",
			transport, tier, fails, time.Since(start).Round(time.Second),
			mb(s.heapAlloc), dmb(s.heapAlloc, base.heapAlloc), mb(s.heapInuse), dmb(s.heapInuse, base.heapInuse),
			mb(s.sys), dmb(s.sys, base.sys), mb(s.rss), dmb(s.rss, base.rss),
			(float64(s.heapInuse)-float64(base.heapInuse))/1024/float64(tier),
			(float64(s.sys)-float64(base.sys))/1024/float64(tier), runtime.NumGoroutine())
		if os.Getenv("MIERU_DUMP") == "1" {
			var sb strings.Builder
			_ = pprof.Lookup("goroutine").WriteTo(&sb, 1)
			t.Logf("[%s] goroutine profile after N=%d:\n%s", transport, tier, sb.String())
		}
	}
}

func phaseB(t *testing.T, conc, secs int) {
	v, port := memSetup(t, "tcp")
	for i := 0; i < 5; i++ {
		c, err := memClient(port, false)
		if err != nil {
			t.Fatal(err)
		}
		_ = memFetch(c, v.target.URL, 1024, 0, 20*time.Second)
		_ = c.Stop()
	}
	base := takeMem(true, true)
	t.Logf("[long] baseline HeapInuse=%sMB Sys=%sMB RSS=%sMB", mb(base.heapInuse), mb(base.sys), mb(base.rss))

	var peakMu sync.Mutex
	var peak memSample
	stop := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		n := 0
		for {
			select {
			case <-stop:
				return
			case <-time.After(250 * time.Millisecond):
			}
			n++
			s := takeMem(false, n%8 == 0)
			peakMu.Lock()
			peak.heapAlloc = max(peak.heapAlloc, s.heapAlloc)
			peak.heapInuse = max(peak.heapInuse, s.heapInuse)
			peak.sys = max(peak.sys, s.sys)
			peak.rss = max(peak.rss, s.rss)
			peakMu.Unlock()
		}
	}()

	const total = 3 << 20 // 3 MiB over `secs` seconds per session
	var wg sync.WaitGroup
	var fails, ok int
	var mu sync.Mutex
	var firstErr error
	t0 := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := memClient(port, false)
			if err == nil {
				defer c.Stop()
				err = memFetch(c, v.target.URL, total, time.Duration(secs)*time.Second, time.Duration(secs+60)*time.Second)
			}
			mu.Lock()
			if err != nil {
				fails++
				if firstErr == nil {
					firstErr = err
				}
			} else {
				ok++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(stop)
	sampler.Wait()
	time.Sleep(2 * time.Second)
	after := takeMem(true, true)
	peakMu.Lock()
	defer peakMu.Unlock()
	t.Logf("[long] conc=%d secs=%d ok=%d fails=%d firstErr=%v elapsed=%s", conc, secs, ok, fails, firstErr, time.Since(t0).Round(time.Second))
	t.Logf("[long] PEAK HeapAlloc=%sMB (%sMB) HeapInuse=%sMB (%sMB) Sys=%sMB (%sMB) RSS=%sMB (%sMB) | per-session peak HeapInuse=%.1fKB",
		mb(peak.heapAlloc), dmb(peak.heapAlloc, base.heapAlloc), mb(peak.heapInuse), dmb(peak.heapInuse, base.heapInuse),
		mb(peak.sys), dmb(peak.sys, base.sys), mb(peak.rss), dmb(peak.rss, base.rss),
		(float64(peak.heapInuse)-float64(base.heapInuse))/1024/float64(conc))
	t.Logf("[long] AFTER GC HeapInuse=%sMB (%sMB) Sys=%sMB RSS=%sMB (%sMB)", mb(after.heapInuse), dmb(after.heapInuse, base.heapInuse), mb(after.sys), mb(after.rss), dmb(after.rss, base.rss))
}

// replayFill drives the library's real ReplayCache past its capacity twice, so
// the current and previous maps are both full (2*capacity entries): the worst
// case of one cache.
func replayFill(t *testing.T, tag string, capacity int) {
	before := takeMem(true, true)
	c := replay.NewCache(capacity, time.Hour)
	var buf [16]byte
	x := uint64(0x9E3779B97F4A7C15)
	for i := 0; i < 2*capacity; i++ {
		for j := 0; j < 2; j++ {
			x += 0x9E3779B97F4A7C15
			z := x
			z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
			z = (z ^ (z >> 27)) * 0x94D049BB133111EB
			binary.LittleEndian.PutUint64(buf[j*8:], z^(z>>31))
		}
		c.IsDuplicate(buf[:], tag)
	}
	cur, prev := c.Sizes()
	after := takeMem(true, true)
	t.Logf("[replay cap=%d tag=%q] entries current=%d previous=%d | HeapInuse %+.1fMB Sys %+.1fMB RSS %+.1fMB | per entry = %.1f B",
		capacity, tag, cur, prev,
		float64(after.heapInuse-before.heapInuse)/1048576, (float64(after.sys)-float64(before.sys))/1048576,
		(float64(after.rss)-float64(before.rss))/1048576,
		float64(after.heapInuse-before.heapInuse)/float64(cur+prev))
	runtime.KeepAlive(c)
}

func TestMieruMemory(t *testing.T) {
	if os.Getenv("MIERU_MEM") != "1" {
		t.Skip("set MIERU_MEM=1 to run the mieru memory measurement")
	}
	t.Run("A_tcp_sessions", func(t *testing.T) { phaseA(t, "tcp", memTiers(t, []int{500, 2000, 5000})) })
	t.Run("B_tcp_long", func(t *testing.T) {
		conc, secs := 200, 30
		if s := os.Getenv("MIERU_LONG"); s != "" {
			conc, _ = strconv.Atoi(s)
		}
		if s := os.Getenv("MIERU_LONG_SECS"); s != "" {
			secs, _ = strconv.Atoi(s)
		}
		phaseB(t, conc, secs)
	})
	t.Run("C_udp_sessions", func(t *testing.T) { phaseA(t, "udp", memTiers(t, []int{500, 2000})) })
	t.Run("D_replay_cache_full", func(t *testing.T) {
		if os.Getenv("MIERU_REPLAY") == "0" {
			t.Skip("MIERU_REPLAY=0")
		}
		// 262144 is the advice for 512 MB hosts, the default is what a fresh
		// config gets, and the library's own size is kept for comparison.
		for _, n := range []int{262144, prismmieru.DefaultReplayCacheEntries, protocol.DefaultReplayCacheEntries} {
			replayFill(t, "", n)
			replayFill(t, "127.0.0.1:12345", n)
		}
	})
}
