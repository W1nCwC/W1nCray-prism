// Package gate is the per-user admission, accounting and kick layer of the
// Prism kernel. The inbounds ask it whether a panel user id is known; the
// router tracker it also implements counts, limits and registers every routed
// connection so a removed user can be kicked.
//
// Users are keyed by the stable panel user id, never by a list index
// (handoff 43 §1.4).
package gate

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
)

// User is one panel user of an inbound. Secret is the user's uuid; every
// protocol derives its credentials from it.
type User struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	SpeedBps    int64  `json:"speed_bps"`
	DeviceLimit int    `json:"device_limit"`
}

// Gate holds the user tables of every inbound tag. The zero value is not
// usable; use New.
type Gate struct {
	mu   sync.Mutex
	tags map[string]*tagState
	// alive is the panel's global device count per tag and user (PUT /v1/devices).
	alive map[string]map[int]int
	snap  uint64
}

type tagState struct {
	seq   int64
	users atomic.Pointer[map[int]*userState]
}

type userState struct {
	user  User
	up    atomic.Int64
	down  atomic.Int64
	limit *limiter

	mu    sync.Mutex
	conns map[*conn]struct{}
	ips   map[netip.Addr]int
}

// Default is the process-wide gate of the program; an engine hands its gate to
// the inbounds through the context (WithContext), tests use their own.
var Default = New()

type ctxKey struct{}

// WithContext returns ctx carrying g.
func WithContext(ctx context.Context, g *Gate) context.Context {
	return context.WithValue(ctx, ctxKey{}, g)
}

// From returns the gate carried by ctx, or Default.
func From(ctx context.Context) *Gate {
	if g, ok := ctx.Value(ctxKey{}).(*Gate); ok && g != nil {
		return g
	}

	return Default
}

func New() *Gate {
	return &Gate{tags: map[string]*tagState{}, alive: map[string]map[int]int{}}
}

func (g *Gate) tag(tag string) *tagState {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.tags[tag]
	if t == nil {
		t = &tagState{}
		empty := map[int]*userState{}
		t.users.Store(&empty)
		g.tags[tag] = t
	}
	return t
}

// Known reports whether id is a user of the inbound tag right now.
func (g *Gate) Known(tag string, id int) bool {
	g.mu.Lock()
	t := g.tags[tag]
	g.mu.Unlock()
	if t == nil {
		return false
	}
	_, ok := (*t.users.Load())[id]

	return ok
}

// KnownName is Known for a protocol that carries the user as a string.
func (g *Gate) KnownName(tag, name string) (int, bool) {
	id, err := strconv.Atoi(name)
	if err != nil {
		return 0, false
	}

	return id, g.Known(tag, id)
}

// Users returns a copy of the current user list of a tag, in id order.
func (g *Gate) Users(tag string) []User {
	g.mu.Lock()
	t := g.tags[tag]
	g.mu.Unlock()
	if t == nil {
		return nil
	}
	m := *t.users.Load()
	out := make([]User, 0, len(m))
	for _, u := range m {
		out = append(out, u.user)
	}
	sortUsers(out)

	return out
}

// Replace swaps the whole user set of a tag atomically and kicks every
// connection of a removed user. A request with a lower seq than the last
// applied one is dropped (returns applied=false). Counters and live
// connections of users that stay are kept.
func (g *Gate) Replace(tag string, seq int64, users []User) (added, removed, kicked int, applied bool) {
	t := g.tag(tag)
	g.mu.Lock()
	if seq != 0 && seq < t.seq {
		g.mu.Unlock()

		return 0, 0, 0, false
	}
	if seq != 0 {
		t.seq = seq
	}
	old := *t.users.Load()
	next := make(map[int]*userState, len(users))
	for _, u := range users {
		if prev, ok := old[u.ID]; ok {
			prev.mu.Lock()
			prev.user = u
			prev.mu.Unlock()
			prev.limit.set(u.SpeedBps)
			next[u.ID] = prev

			continue
		}
		added++
		next[u.ID] = &userState{user: u, limit: newLimiter(u.SpeedBps), conns: map[*conn]struct{}{}, ips: map[netip.Addr]int{}}
	}
	var gone []*userState
	for id, s := range old {
		if _, ok := next[id]; !ok {
			removed++
			gone = append(gone, s)
		}
	}
	t.users.Store(&next)
	g.mu.Unlock()

	for _, s := range gone {
		kicked += s.kickAll()
	}

	return added, removed, kicked, true
}

// Seq returns the last applied sequence number of a tag.
func (g *Gate) Seq(tag string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t := g.tags[tag]; t != nil {
		return t.seq
	}

	return 0
}

// Counts returns the number of users and live connections of a tag.
func (g *Gate) Counts(tag string) (users, conns int) {
	g.mu.Lock()
	t := g.tags[tag]
	g.mu.Unlock()
	if t == nil {
		return 0, 0
	}
	m := *t.users.Load()
	for _, s := range m {
		s.mu.Lock()
		conns += len(s.conns)
		s.mu.Unlock()
	}

	return len(m), conns
}

// Drop forgets every tag not in keep (its inbound is gone from the config).
func (g *Gate) Drop(tags map[string]bool) {
	g.mu.Lock()
	var gone []*tagState
	for tag, t := range g.tags {
		if !tags[tag] {
			gone = append(gone, t)
			delete(g.tags, tag)
			delete(g.alive, tag)
		}
	}
	g.mu.Unlock()
	for _, t := range gone {
		for _, s := range *t.users.Load() {
			s.kickAll()
		}
	}
}

// SetAlive stores the panel's global device count per user of a tag.
func (g *Gate) SetAlive(tag string, alive map[int]int) {
	g.mu.Lock()
	g.alive[tag] = alive
	g.mu.Unlock()
}

func (g *Gate) aliveOf(tag string, id int) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.alive[tag][id]
}

func (g *Gate) state(tag string, id int) *userState {
	g.mu.Lock()
	t := g.tags[tag]
	g.mu.Unlock()
	if t == nil {
		return nil
	}

	return (*t.users.Load())[id]
}

func sortUsers(u []User) {
	for i := 1; i < len(u); i++ {
		for j := i; j > 0 && u[j-1].ID > u[j].ID; j-- {
			u[j-1], u[j] = u[j], u[j-1]
		}
	}
}
