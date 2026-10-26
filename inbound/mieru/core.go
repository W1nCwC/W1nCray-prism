package mieru

// This is the only file that touches the packages of the Prism kernel's
// transport library (github.com/enfein/mieru/v3, GPL-3.0-or-later) outside of
// its public apis/ tree. When the library changes, patch it here.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

// maxCredentialLen is the library's limit for user names and passwords.
const maxCredentialLen = 64

// credential is one user of the server.
type credential struct {
	name     string
	password string
}

type muxHandle struct{ m *protocol.Mux }

var quiet sync.Once

// checkTrafficPattern validates the base64 pattern of a config.
func checkTrafficPattern(encoded string) error {
	if encoded == "" {
		return nil
	}
	pattern, err := trafficpattern.Decode(encoded)
	if err != nil {
		return err
	}
	_, err = trafficpattern.NewConfig(pattern)

	return err
}

func toUsers(list []credential) map[string]*appctlpb.User {
	users := make(map[string]*appctlpb.User, len(list))
	for _, c := range list {
		users[c.name] = &appctlpb.User{Name: proto.String(c.name), Password: proto.String(c.password)}
	}

	return users
}

// serverTCPIdleTimeout closes a TCP underlay that has carried nothing in either
// direction for this long. The library keeps such connections forever by
// default (about 20 KB each), which a scanner can use to exhaust a small host.
const serverTCPIdleTimeout = 10 * time.Minute

// newMux builds and starts the multiplexer. The library refuses to start
// without a user, so an empty list gets one unguessable placeholder that no
// panel user can be (names are decimal ids), and the first update replaces it.
func newMux(addr *net.TCPAddr, udp bool, trafficPattern string, list []credential) (*muxHandle, error) {
	quiet.Do(func() { log.SetFormatter(&log.NilFormatter{}) })
	var pattern *appctlpb.TrafficPattern
	if trafficPattern != "" {
		p, err := trafficpattern.Decode(trafficPattern)
		if err != nil {
			return nil, err
		}
		pattern = p
	}
	cfg, err := trafficpattern.NewConfig(pattern)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		list = placeholder()
	}
	m := protocol.NewMux(false)
	m.SetTrafficPattern(cfg).SetServerUsers(toUsers(list)).SetServerTCPIdleTimeout(serverTCPIdleTimeout)
	var endpoint protocol.UnderlayProperties
	if udp {
		endpoint = protocol.NewUnderlayProperties(common.DefaultMTU, common.PacketTransport, &net.UDPAddr{IP: addr.IP, Port: addr.Port}, nil)
	} else {
		endpoint = protocol.NewUnderlayProperties(common.DefaultMTU, common.StreamTransport, addr, nil)
	}
	m.SetEndpoints([]protocol.UnderlayProperties{endpoint})
	if err := m.Start(); err != nil {
		_ = m.Close()

		return nil, err
	}

	return &muxHandle{m: m}, nil
}

func placeholder() []credential {
	var b [16]byte
	_, _ = rand.Read(b[:])
	var p [16]byte
	_, _ = rand.Read(p[:])

	return []credential{{name: "x" + hex.EncodeToString(b[:]), password: hex.EncodeToString(p[:])}}
}

func (h *muxHandle) accept() (net.Conn, error) { return h.m.Accept() }

// setUsers atomically replaces the user table; an empty list is allowed.
func (h *muxHandle) setUsers(list []credential) {
	if len(list) == 0 {
		list = placeholder()
	}
	h.m.SetServerUsers(toUsers(list))
}

func (h *muxHandle) close() error { return h.m.Close() }

// userName returns the authenticated user of an accepted session.
func userName(conn net.Conn) (string, error) {
	uc, ok := conn.(apicommon.UserContext)
	if !ok {
		return "", errors.New("session carries no user")
	}

	return uc.UserName(), nil
}

func checkCredential(c credential) error {
	if c.name == "" || c.password == "" {
		return errors.New("empty user name or password")
	}
	if len(c.name) > maxCredentialLen || len(c.password) > maxCredentialLen {
		return fmt.Errorf("user name and password are limited to %d bytes", maxCredentialLen)
	}

	return nil
}

// Replay cache sizing. The library keeps two process-wide replay caches (one
// for streams, one for packets), so the capacity is a property of the process,
// not of one inbound. Every running inbound registers the capacity it wants
// and the largest one is in effect: a smaller cache would silently weaken the
// replay protection of the inbound that asked for more. The value is
// recomputed when an inbound starts or stops, so a config reload that lowers
// the number takes effect once the old inbound is gone. A change drops the
// signatures stored so far (a short window without replay detection).
const (
	// DefaultReplayCacheEntries is used when replay_cache_entries is 0.
	DefaultReplayCacheEntries = 1048576
	// MinReplayCacheEntries and MaxReplayCacheEntries bound replay_cache_entries.
	MinReplayCacheEntries = 4096
	MaxReplayCacheEntries = 4 * 1024 * 1024 // the library's own default
)

var (
	replayMu   sync.Mutex
	replayWant = map[*Inbound]int{}
)

// checkReplayEntries validates the replay_cache_entries option (0 = default).
func checkReplayEntries(n int) error {
	if n == 0 {
		return nil
	}
	if n < MinReplayCacheEntries || n > MaxReplayCacheEntries {
		return fmt.Errorf("replay_cache_entries must be 0 (default %d) or between %d and %d", DefaultReplayCacheEntries, MinReplayCacheEntries, MaxReplayCacheEntries)
	}

	return nil
}

// useReplayEntries registers what h wants and applies the largest request.
func useReplayEntries(h *Inbound, n int) {
	if n == 0 {
		n = DefaultReplayCacheEntries
	}
	replayMu.Lock()
	defer replayMu.Unlock()
	replayWant[h] = n
	applyReplayEntriesLocked()
}

// releaseReplayEntries drops the request of h; the rest keep their maximum.
func releaseReplayEntries(h *Inbound) {
	replayMu.Lock()
	defer replayMu.Unlock()
	if _, ok := replayWant[h]; !ok {
		return
	}
	delete(replayWant, h)
	applyReplayEntriesLocked()
}

func applyReplayEntriesLocked() {
	most := 0
	for _, n := range replayWant {
		if n > most {
			most = n
		}
	}
	if most > 0 {
		protocol.SetReplayCacheCapacity(most, most)
	}
}
