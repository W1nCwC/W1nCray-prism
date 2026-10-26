// Package mieru is the Prism kernel's mieru inbound with hot user replacement.
// It does not use the library's ready-made server: that one takes its users
// once, reads the first request of every session in the accept call and has no
// traffic hooks. The multiplexer is driven directly and every session is
// handled in its own goroutine. The user name of a session is the stable panel
// user id, the password is the user's uuid.
package mieru

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// Type is the inbound type name.
const Type = "mieru"

func Register(registry *inbound.Registry) {
	inbound.Register[Options](registry, Type, New)
}

type Inbound struct {
	inbound.Adapter
	gate    *gate.Gate
	router  adapter.ConnectionRouterEx
	logger  logger.ContextLogger
	options Options
	udp     bool

	mu      sync.Mutex
	mux     *muxHandle
	users   []credential
	known   map[string]bool
	conns   map[net.Conn]string // live sessions -> user name
	stopped bool
	done    chan struct{}
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	var udp bool
	switch options.Transport {
	case "", "tcp":
	case "udp":
		udp = true
	default:
		return nil, E.New("transport must be tcp or udp, not ", options.Transport)
	}
	if options.ListenPort == 0 {
		return nil, E.New("listen_port is required (a single port; port ranges are not supported)")
	}
	if len(options.TrafficPattern) > maxPatternLen {
		return nil, E.New("traffic_pattern is longer than ", maxPatternLen, " bytes")
	}
	if err := checkTrafficPattern(options.TrafficPattern); err != nil {
		return nil, E.Cause(err, "traffic_pattern")
	}
	if err := checkReplayEntries(options.ReplayCacheEntries); err != nil {
		return nil, E.Cause(err, "replay_cache_entries")
	}

	return &Inbound{
		Adapter: inbound.NewAdapter(Type, tag),
		gate:    gate.From(ctx),
		router:  router,
		logger:  logger,
		options: options,
		udp:     udp,
		conns:   map[net.Conn]string{},
		done:    make(chan struct{}),
	}, nil
}

// maxPatternLen bounds the base64 traffic pattern of a config.
const maxPatternLen = 2048

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	addr := h.options.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	h.mu.Lock()
	users := append([]credential(nil), h.users...)
	h.mu.Unlock()
	useReplayEntries(h, h.options.ReplayCacheEntries)
	m, err := newMux(&net.TCPAddr{IP: addr.AsSlice(), Port: int(h.options.ListenPort)}, h.udp, h.options.TrafficPattern, users)
	if err != nil {
		releaseReplayEntries(h)
		return err
	}
	h.mu.Lock()
	h.mux = m
	h.mu.Unlock()
	go h.acceptLoop(m)
	scope.Add(h.stop)

	return nil
}

// stop closes the multiplexer and every session it has handed out: the
// library's own close leaves established sessions alone, which would keep
// serving on a stale multiplexer after a config change.
func (h *Inbound) stop() error {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()

		return nil
	}
	h.stopped = true
	releaseReplayEntries(h)
	m := h.mux
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	var err error
	if m != nil {
		err = m.close()
		<-h.done
	}
	for _, c := range conns {
		_ = c.Close()
	}

	return err
}

func (h *Inbound) track(c net.Conn, name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return false
	}
	h.conns[c] = name

	return true
}

func (h *Inbound) untrack(c net.Conn) {
	h.mu.Lock()
	delete(h.conns, c)
	h.mu.Unlock()
}

// named records the user of a tracked session; false when the inbound has
// stopped or the user has meanwhile left.
func (h *Inbound) named(c net.Conn, name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.conns[c]; !ok {
		return false
	}
	if !h.known[name] {
		return false
	}
	h.conns[c] = name

	return true
}
