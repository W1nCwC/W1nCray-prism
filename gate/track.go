package gate

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

// limiter is a shared token bucket of one user (0 = unlimited).
type limiter struct {
	l atomic.Pointer[rate.Limiter]
}

func newLimiter(bps int64) *limiter {
	lm := &limiter{}
	lm.set(bps)

	return lm
}

func (l *limiter) set(bps int64) {
	if bps <= 0 {
		l.l.Store(nil)

		return
	}
	burst := int(bps)
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	if cur := l.l.Load(); cur != nil && cur.Limit() == rate.Limit(bps) {
		return
	}
	l.l.Store(rate.NewLimiter(rate.Limit(bps), burst))
}

// wait blocks until n bytes may pass.
func (l *limiter) wait(n int) {
	lim := l.l.Load()
	if lim == nil || n <= 0 {
		return
	}
	for n > 0 {
		step := min(n, lim.Burst())
		_ = lim.WaitN(context.Background(), step)
		n -= step
	}
}

// conn is a counted, rate limited, kickable connection.
type conn struct {
	net.Conn
	s      *userState
	ip     netip.Addr
	closed sync.Once
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.s.up.Add(int64(n))
		c.s.limit.wait(n)
	}

	return n, err
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.s.down.Add(int64(n))
		c.s.limit.wait(n)
	}

	return n, err
}

func (c *conn) Close() error {
	c.closed.Do(func() { c.s.forget(c) })

	return c.Conn.Close()
}

// packetConn is conn for UDP associations.
type packetConn struct {
	N.PacketConn
	s      *userState
	ip     netip.Addr
	closed sync.Once
	reg    *conn
}

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := buffer.Len()
		c.s.up.Add(int64(n))
		c.s.limit.wait(n)
	}

	return destination, err
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := buffer.Len()
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		c.s.down.Add(int64(n))
		c.s.limit.wait(n)
	}

	return err
}

func (c *packetConn) Close() error {
	c.closed.Do(func() { c.s.forget(c.reg) })

	return c.PacketConn.Close()
}

func (s *userState) forget(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	if c.ip.IsValid() {
		if s.ips[c.ip]--; s.ips[c.ip] <= 0 {
			delete(s.ips, c.ip)
		}
	}
	s.mu.Unlock()
}

// register adds a connection unless the user already uses its device limit
// from other addresses. ok=false means the connection must be refused.
func (s *userState) register(c *conn, aliveElsewhere int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.user.DeviceLimit
	if limit > 0 && c.ip.IsValid() {
		if _, known := s.ips[c.ip]; !known && len(s.ips)+aliveElsewhere >= limit {
			return false
		}
	}
	s.conns[c] = struct{}{}
	if c.ip.IsValid() {
		s.ips[c.ip]++
	}

	return true
}

// kickAll closes every live connection of the user.
func (s *userState) kickAll() int {
	s.mu.Lock()
	list := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		list = append(list, c)
	}
	s.mu.Unlock()
	for _, c := range list {
		_ = c.Conn.Close()
		s.forget(c)
	}

	return len(list)
}

// ---- adapter.ConnectionTracker ----------------------------------------------

// RoutedConnection implements adapter.ConnectionTracker.
func (g *Gate) RoutedConnection(_ context.Context, c net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	s, ip, ok := g.lookup(m)
	if !ok {
		return c
	}
	wrapped := &conn{Conn: c, s: s, ip: ip}
	if !s.register(wrapped, g.aliveOf(m.Inbound, s.user.ID)) {
		_ = c.Close()

		return &deadConn{Conn: c}
	}

	return wrapped
}

// RoutedPacketConnection implements adapter.ConnectionTracker.
func (g *Gate) RoutedPacketConnection(_ context.Context, c N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	s, ip, ok := g.lookup(m)
	if !ok {
		return c
	}
	reg := &conn{Conn: closerConn{closer: c}, s: s, ip: ip}
	if !s.register(reg, g.aliveOf(m.Inbound, s.user.ID)) {
		_ = c.Close()

		return c
	}

	return &packetConn{PacketConn: c, s: s, ip: ip, reg: reg}
}

// RoutedFlow implements adapter.ConnectionTracker.
func (g *Gate) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

func (g *Gate) lookup(m adapter.InboundContext) (*userState, netip.Addr, bool) {
	if m.User == "" {
		return nil, netip.Addr{}, false
	}
	id, err := strconv.Atoi(m.User)
	if err != nil {
		return nil, netip.Addr{}, false
	}
	s := g.state(m.Inbound, id)
	if s == nil {
		return nil, netip.Addr{}, false
	}

	return s, m.Source.Addr.Unmap(), true
}

// ---- stats --------------------------------------------------------------------

// Traffic is the unreported usage of one user.
type Traffic struct {
	ID   int   `json:"id"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Alive is the set of client addresses a user is connected from.
type Alive struct {
	ID  int      `json:"id"`
	IPs []string `json:"ips"`
}

type snapshot struct {
	id    uint64
	taken map[int]Traffic
}

var snapshots sync.Map // tag -> *snapshot

// Snapshot records the current unreported usage of a tag (replacing any older
// snapshot of that tag) and returns it. Nothing is subtracted until Commit.
func (g *Gate) Snapshot(tag string) (id uint64, traffic []Traffic, alive []Alive, ok bool) {
	g.mu.Lock()
	t := g.tags[tag]
	g.snap++
	id = g.snap
	g.mu.Unlock()
	if t == nil {
		return 0, nil, nil, false
	}
	taken := map[int]Traffic{}
	for uid, s := range *t.users.Load() {
		up, down := s.up.Load(), s.down.Load()
		if up > 0 || down > 0 {
			taken[uid] = Traffic{ID: uid, Up: up, Down: down}
			traffic = append(traffic, taken[uid])
		}
		s.mu.Lock()
		if len(s.ips) > 0 {
			a := Alive{ID: uid}
			for ip := range s.ips {
				a.IPs = append(a.IPs, ip.String())
			}
			alive = append(alive, a)
		}
		s.mu.Unlock()
	}
	snapshots.Store(tag, &snapshot{id: id, taken: taken})

	return id, traffic, alive, true
}

// Commit subtracts the usage recorded by snapshot id. It returns false when
// the snapshot is not the current one of the tag (409 on the IPC).
func (g *Gate) Commit(tag string, id uint64) bool {
	v, ok := snapshots.Load(tag)
	if !ok || v.(*snapshot).id != id {
		return false
	}
	snapshots.Delete(tag)
	g.mu.Lock()
	t := g.tags[tag]
	g.mu.Unlock()
	if t == nil {
		return true
	}
	users := *t.users.Load()
	for uid, tr := range v.(*snapshot).taken {
		if s := users[uid]; s != nil {
			s.up.Add(-tr.Up)
			s.down.Add(-tr.Down)
		}
	}

	return true
}

// ---- small helpers ----------------------------------------------------------

type deadConn struct{ net.Conn }

func (deadConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (deadConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

type closerConn struct {
	net.Conn
	closer interface{ Close() error }
}

func (c closerConn) Close() error { return c.closer.Close() }

// Wait is exported for tests that need to let the limiter refill.
func Wait(d time.Duration) { time.Sleep(d) }
