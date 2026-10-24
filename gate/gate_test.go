package gate

import (
	"net"
	"net/netip"
	"testing"
)

func TestReplaceKeepsCountersAndKicksRemovedUsers(t *testing.T) {
	g := New()
	added, removed, _, ok := g.Replace("in", 1, []User{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}})
	if !ok || added != 2 || removed != 0 {
		t.Fatalf("first replace: added=%d removed=%d ok=%v", added, removed, ok)
	}
	s1, s2 := g.state("in", 1), g.state("in", 2)
	s1.up.Add(10)

	c1, c1peer := net.Pipe()
	defer c1peer.Close()
	wrapped := &conn{Conn: c1, s: s2, ip: netip.MustParseAddr("192.0.2.1")}
	if !s2.register(wrapped, 0) {
		t.Fatal("register refused")
	}

	added, removed, kicked, ok := g.Replace("in", 2, []User{{ID: 1, UUID: "a2"}})
	if !ok || added != 0 || removed != 1 || kicked != 1 {
		t.Fatalf("second replace: added=%d removed=%d kicked=%d ok=%v", added, removed, kicked, ok)
	}
	if g.state("in", 1) != s1 || s1.up.Load() != 10 {
		t.Fatal("a surviving user lost its state")
	}
	if g.Known("in", 2) {
		t.Fatal("a removed user is still known")
	}
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Fatal("the removed user's connection is still open")
	}
}

func TestOldSequencesAreDropped(t *testing.T) {
	g := New()
	g.Replace("in", 5, []User{{ID: 1, UUID: "a"}})
	if _, _, _, ok := g.Replace("in", 4, []User{{ID: 2, UUID: "b"}}); ok {
		t.Fatal("an older seq was applied")
	}
	if _, _, _, ok := g.Replace("in", 0, []User{{ID: 3, UUID: "c"}}); !ok {
		t.Fatal("seq 0 (unordered) must always apply")
	}
}

func TestDeviceLimitCountsDistinctAddresses(t *testing.T) {
	g := New()
	g.Replace("in", 1, []User{{ID: 1, UUID: "a", DeviceLimit: 2}})
	s := g.state("in", 1)
	mk := func(ip string) *conn {
		c, p := net.Pipe()
		t.Cleanup(func() { c.Close(); p.Close() })

		return &conn{Conn: c, s: s, ip: netip.MustParseAddr(ip)}
	}
	a, a2, b, c3 := mk("192.0.2.1"), mk("192.0.2.1"), mk("192.0.2.2"), mk("192.0.2.3")
	if !s.register(a, 0) || !s.register(a2, 0) {
		t.Fatal("two connections of one address must both be allowed")
	}
	if !s.register(b, 0) {
		t.Fatal("the second address must be allowed")
	}
	if s.register(c3, 0) {
		t.Fatal("a third address passed a device limit of 2")
	}
	s.forget(a)
	s.forget(a2)
	if !s.register(c3, 0) {
		t.Fatal("a slot should be free after one address left")
	}
	// Devices alive on other nodes count against the same limit.
	d := mk("192.0.2.9")
	if s.register(d, 1) {
		t.Fatal("the panel-wide alive count was ignored")
	}
}

func TestCountsAndDrop(t *testing.T) {
	g := New()
	g.Replace("a", 1, []User{{ID: 1, UUID: "x"}})
	g.Replace("b", 1, []User{{ID: 1, UUID: "x"}, {ID: 2, UUID: "y"}})
	if u, _ := g.Counts("b"); u != 2 {
		t.Fatalf("users of b = %d", u)
	}
	g.Drop(map[string]bool{"a": true})
	if g.Known("b", 1) || !g.Known("a", 1) {
		t.Fatal("Drop kept the wrong tags")
	}
}

func TestLimiterRefusesNothingWhenUnlimited(t *testing.T) {
	l := newLimiter(0)
	l.wait(1 << 30) // must return at once
	l.set(1 << 20)
	l.wait(0)
}
