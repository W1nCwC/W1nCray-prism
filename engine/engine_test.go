package engine

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

const mib = 1 << 20

var quicKinds = []string{"tuic", "hysteria", "hysteria2", "anytls"}

func TestEveryProtocolCarriesTrafficAndCountsIt(t *testing.T) {
	v := newEnv(t)
	ports := map[string]int{}
	var ins []string
	for _, k := range append(append([]string{}, quicKinds...), "naive") {
		ports[k] = freePort(t)
		ins = append(ins, v.inbound(k, k, ports[k]))
	}
	if err := v.apply("h1", serverConfig(ins...)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for k := range ports {
		v.setUsers(k, 1, gate.User{ID: 1001, UUID: uuidA})
	}
	outs := map[string]string{}
	for _, k := range quicKinds {
		outs[k] = clientOutbound(k, "o-"+k, ports[k], uuidA)
	}
	c := newClient(t, outs)

	for _, k := range quicKinds {
		got, err := fetch(c.proxy(k), v.target.URL, mib, 0)
		if err != nil || got != mib {
			t.Fatalf("%s: got=%d err=%v", k, got, err)
		}
	}
	got, err := naiveFetch("127.0.0.1:"+strconv.Itoa(ports["naive"]), "1001", uuidA, v.target.URL, mib, 0)
	if err != nil || got != mib {
		t.Fatalf("naive: got=%d err=%v", got, err)
	}

	for k := range ports {
		_, traffic, _, ok := v.g.Snapshot(k)
		if !ok {
			t.Fatalf("%s: no snapshot", k)
		}
		var sum int64
		for _, tr := range traffic {
			if tr.ID != 1001 {
				t.Fatalf("%s: traffic of unexpected user %d", k, tr.ID)
			}
			sum += tr.Up + tr.Down
		}
		if sum < mib {
			t.Fatalf("%s: counted %d bytes, want >= %d", k, sum, mib)
		}
	}
}

func TestUnknownUsersAreRefusedAndHotAddRemoveKicks(t *testing.T) {
	for _, kind := range []string{"tuic", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			v := newEnv(t)
			port := freePort(t)
			if err := v.apply("h1", serverConfig(v.inbound(kind, "in", port))); err != nil {
				t.Fatal(err)
			}
			v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
			c := newClient(t, map[string]string{
				"a": clientOutbound(kind, "o-a", port, uuidA),
				"b": clientOutbound(kind, "o-b", port, uuidB),
			})

			if _, err := fetch(c.proxy("b"), v.target.URL, 1024, 0); err == nil {
				t.Fatal("unknown user 1002 was served")
			}

			// A slow download of 1001 spans the addition of 1002.
			slow := goFetch(c.proxy("a"), v.target.URL, mib, 3*time.Second)
			time.Sleep(800 * time.Millisecond)
			v.setUsers("in", 2, gate.User{ID: 1001, UUID: uuidA}, gate.User{ID: 1002, UUID: uuidB})
			if _, err := fetch(c.proxy("b"), v.target.URL, 1024, 0); err != nil {
				t.Fatalf("new user 1002 refused after the update: %v", err)
			}
			if r := <-slow; r.err != nil {
				t.Fatalf("in-flight 1001 download broke on the update: %v", r.err)
			}

			// Remove 1001 while it downloads: the connection is kicked.
			slow = goFetch(c.proxy("a"), v.target.URL, mib, 3*time.Second)
			time.Sleep(800 * time.Millisecond)
			_, removed, kicked, _, err := v.e.SetUsers("in", 3, []gate.User{{ID: 1002, UUID: uuidB}})
			if err != nil || removed != 1 {
				t.Fatalf("remove: removed=%d err=%v", removed, err)
			}
			if r := <-slow; r.err == nil {
				t.Fatalf("a removed user finished its download (kicked=%d)", kicked)
			}
			if kicked < 1 {
				t.Fatalf("nothing was kicked")
			}
			if _, err := fetch(c.proxy("a"), v.target.URL, 1024, 0); err == nil {
				t.Fatal("removed user 1001 was served afterwards")
			}
			if _, err := fetch(c.proxy("b"), v.target.URL, 1024, 0); err != nil {
				t.Fatalf("remaining user 1002 was disturbed: %v", err)
			}
		})
	}
}

func TestNaiveRefusesWrongAndRemovedUsers(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(v.inbound("naive", "in", port))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 7, UUID: uuidA})
	addr := "127.0.0.1:" + strconv.Itoa(port)

	if _, err := naiveFetch(addr, "7", uuidA, v.target.URL, 1024, 0); err != nil {
		t.Fatalf("good credentials refused: %v", err)
	}
	if _, err := naiveFetch(addr, "7", "wrong", v.target.URL, 1024, 0); err == nil {
		t.Fatal("wrong password accepted")
	}
	v.setUsers("in", 2, gate.User{ID: 8, UUID: uuidB})
	if _, err := naiveFetch(addr, "7", uuidA, v.target.URL, 1024, 0); err == nil {
		t.Fatal("removed user accepted")
	}
}

func TestInvalidConfigKeepsTheRunningOne(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("good", serverConfig(v.inbound("tuic", "in", port))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1, UUID: uuidA})
	c := newClient(t, map[string]string{"a": clientOutbound("tuic", "o-a", port, uuidA)})

	cases := map[string]string{
		"missing cert":   `{"inbounds":[{"type":"tuic","tag":"in","listen":"127.0.0.1","listen_port":1,"tls":{"enabled":true,"certificate_path":"/nonexistent.pem","key_path":"/nonexistent.key"}}]}`,
		"unknown field":  `{"inbounds":[],"nonsense":true}`,
		"foreign type":   `{"inbounds":[{"type":"mixed","tag":"x","listen":"127.0.0.1","listen_port":1}]}`,
		"duplicate tag":  `{"inbounds":[{"type":"anytls","tag":"x","listen":"127.0.0.1","listen_port":2},{"type":"anytls","tag":"x","listen":"127.0.0.1","listen_port":3}]}`,
		"users in cfg":   `{"inbounds":[{"type":"anytls","tag":"x","listen":"127.0.0.1","listen_port":2,"users":[{"name":"1","password":"p"}]}]}`,
		"experimental":   `{"experimental":{"cache_file":{"enabled":true}}}`,
		"not json":       `nope`,
		"hy2 masquerade": `{"inbounds":[{"type":"hysteria2","tag":"x","listen":"127.0.0.1","listen_port":2,"masquerade":"https://example.com"}]}`,
	}
	for name, cfg := range cases {
		_, err := v.e.Apply("bad-"+name, []byte(cfg))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err=%v, want ErrInvalid", name, err)
		}
	}
	s := v.e.Status()
	if s.ConfigHash == nil || *s.ConfigHash != "good" || s.RejectedHash == nil {
		t.Fatalf("status after a rejected config: %+v", s)
	}
	if _, err := fetch(c.proxy("a"), v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the running config stopped serving: %v", err)
	}
}

func TestStartFailureRestoresThePreviousConfig(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("good", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1, UUID: uuidA})

	// A foreign process holds the port the new config wants.
	busyPort := freePort(t)
	busy, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(busyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	_, err = v.e.Apply("busy", []byte(serverConfig(v.inbound("anytls", "in", port), v.inbound("anytls", "other", busyPort))))
	if !errors.Is(err, ErrStart) {
		t.Fatalf("err=%v, want ErrStart", err)
	}
	s := v.e.Status()
	if s.ConfigHash == nil || *s.ConfigHash != "good" {
		t.Fatalf("the previous config was not restored: %+v", s)
	}
	c := newClient(t, map[string]string{"a": clientOutbound("anytls", "o-a", port, uuidA)})
	if _, err := fetch(c.proxy("a"), v.target.URL, 1024, 0); err != nil {
		t.Fatalf("restored config does not serve: %v", err)
	}
}

func TestSameHashIsANoopAndUsersSurviveAConfigChange(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	cfg := serverConfig(v.inbound("hysteria2", "in", port))
	if err := v.apply("h1", cfg); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 5, UUID: uuidA})
	if noop, err := v.e.Apply("h1", []byte(cfg)); err != nil || !noop {
		t.Fatalf("same hash: noop=%v err=%v", noop, err)
	}
	// A new config (the log level differs) rebuilds the core; the user table is kept.
	cfg2 := `{"log":{"level":"warn"}` + cfg[len(`{"log":{"level":"error"}`):]
	if err := v.apply("h2", cfg2); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, map[string]string{"a": clientOutbound("hysteria2", "o-a", port, uuidA)})
	if _, err := fetch(c.proxy("a"), v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the user was lost over a config change: %v", err)
	}
}

func TestUsersForAnUnknownInboundAre404AndOldSequencesAreDropped(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := v.e.SetUsers("nope", 1, nil); err == nil {
		t.Fatal("users for an unknown inbound were accepted")
	}
	if _, _, _, applied, _ := v.e.SetUsers("in", 5, []gate.User{{ID: 1, UUID: uuidA}}); !applied {
		t.Fatal("seq 5 was not applied")
	}
	if _, _, _, applied, _ := v.e.SetUsers("in", 4, []gate.User{{ID: 2, UUID: uuidA}}); applied {
		t.Fatal("seq 4 after seq 5 was applied")
	}
	if got := v.g.Users("in"); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("users = %+v", got)
	}
	if _, _, _, _, err := v.e.SetUsers("in", 6, []gate.User{{ID: 0, UUID: uuidA}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a user without a positive id: err=%v", err)
	}
}

func TestStatsSnapshotAndCommit(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1, UUID: uuidA})
	c := newClient(t, map[string]string{"a": clientOutbound("anytls", "o-a", port, uuidA)})
	if _, err := fetch(c.proxy("a"), v.target.URL, mib, 0); err != nil {
		t.Fatal(err)
	}

	id1, tr1, _, _ := v.g.Snapshot("in")
	sum := func(t []gate.Traffic) (n int64) {
		for _, x := range t {
			n += x.Up + x.Down
		}

		return
	}
	if sum(tr1) < mib {
		t.Fatalf("first snapshot counted %d", sum(tr1))
	}
	// Not committed: the next snapshot still carries the usage.
	id2, tr2, _, _ := v.g.Snapshot("in")
	if sum(tr2) < sum(tr1) {
		t.Fatalf("an uncommitted snapshot lost usage: %d < %d", sum(tr2), sum(tr1))
	}
	if v.g.Commit("in", id1) {
		t.Fatal("a replaced snapshot was committed")
	}
	if !v.g.Commit("in", id2) {
		t.Fatal("the current snapshot was not committed")
	}
	_, tr3, _, _ := v.g.Snapshot("in")
	if sum(tr3) != 0 {
		t.Fatalf("usage after commit = %d, want 0", sum(tr3))
	}
	if v.g.Commit("in", id2) {
		t.Fatal("a snapshot was committed twice")
	}
}

func TestZeroInboundsIsIdleAndStatusHasABootID(t *testing.T) {
	v := newEnv(t)
	if err := v.apply("empty", serverConfig()); err != nil {
		t.Fatal(err)
	}
	s := v.e.Status()
	if s.State != "idle" || s.BootID == "" || s.API != APIVersion {
		t.Fatalf("status = %+v", s)
	}
	port := freePort(t)
	if err := v.apply("one", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	if v.e.Status().State != "running" {
		t.Fatal("not running with an inbound")
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 3, gate.User{ID: 9, UUID: uuidA})
	_ = v.e.Close()

	g2 := gate.New()
	e2, err := New(v.e.dir, g2)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	e2.Restore()
	if e2.BootID() == v.e.BootID() {
		t.Fatal("the boot id did not change")
	}
	if s := e2.Status(); s.ConfigHash == nil || *s.ConfigHash != "h1" {
		t.Fatalf("config not restored: %+v", s)
	}
	if !g2.Known("in", 9) || g2.Seq("in") != 3 {
		t.Fatalf("users not restored: known=%v seq=%d", g2.Known("in", 9), g2.Seq("in"))
	}
	c := newClient(t, map[string]string{"a": clientOutbound("anytls", "o-a", port, uuidA)})
	if _, err := fetch(c.proxy("a"), v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the restored kernel does not serve: %v", err)
	}
}

func TestRateLimitSlowsAUser(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(v.inbound("anytls", "in", port))); err != nil {
		t.Fatal(err)
	}
	// 256 KiB/s on a 1 MiB download should take clearly longer than an unlimited user.
	v.setUsers("in", 1, gate.User{ID: 1, UUID: uuidA, SpeedBps: 256 << 10}, gate.User{ID: 2, UUID: uuidB})
	c := newClient(t, map[string]string{
		"slow": clientOutbound("anytls", "o-slow", port, uuidA),
		"fast": clientOutbound("anytls", "o-fast", port, uuidB),
	})
	t0 := time.Now()
	if _, err := fetch(c.proxy("fast"), v.target.URL, mib, 0); err != nil {
		t.Fatal(err)
	}
	fast := time.Since(t0)
	t0 = time.Now()
	if _, err := fetch(c.proxy("slow"), v.target.URL, mib, 0); err != nil {
		t.Fatal(err)
	}
	slow := time.Since(t0)
	if slow < 2*time.Second || slow < 4*fast {
		t.Fatalf("limited user took %s, unlimited %s: the limit did not bite", slow, fast)
	}
}

type fetchResult struct {
	got int64
	err error
}

func goFetch(proxy, target string, n int, slow time.Duration) chan fetchResult {
	ch := make(chan fetchResult, 1)
	go func() {
		g, e := fetch(proxy, target, n, slow)
		ch <- fetchResult{g, e}
	}()

	return ch
}
