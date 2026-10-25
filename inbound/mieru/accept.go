package mieru

import (
	"context"
	"net"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// handshakeTimeout bounds the wait for the first request of a session.
const handshakeTimeout = 10 * time.Second

func (h *Inbound) acceptLoop(m *muxHandle) {
	defer close(h.done)
	for {
		conn, err := m.accept()
		if err != nil {
			return
		}
		go h.serve(conn)
	}
}

// serve admits one session: the user must be a known panel user, the first
// request is a socks5 CONNECT or UDP ASSOCIATE.
func (h *Inbound) serve(raw net.Conn) {
	conn := &session{Conn: raw, h: h}
	if !h.track(conn, "") {
		_ = conn.Close()

		return
	}
	ctx := log.ContextWithNewID(context.Background())
	onClose := func(error) { _ = conn.Close() }

	// The library learns the user from the first segment, so the name is only
	// reliable after the request has been read.
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	req := &model.Request{}
	if err := req.ReadFromSocks5(conn); err != nil {
		h.logger.DebugContext(ctx, E.Cause(err, "read request"))
		_ = conn.Close()

		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	name, err := userName(raw)
	if err != nil {
		_ = conn.Close()

		return
	}
	if _, ok := h.gate.KnownName(h.Tag(), name); !ok || !h.named(conn, name) {
		_ = conn.Close()

		return
	}

	destination := toSocksaddr(req.DstAddr)
	metadata := adapter.InboundContext{
		Inbound:     h.Tag(),
		InboundType: h.Type(),
		Source:      M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap(),
		Destination: destination,
		User:        name,
	}
	//nolint:staticcheck
	metadata.InboundDetour = h.options.Detour

	switch req.Command {
	case constant.Socks5ConnectCmd:
		if err := reply(conn, constant.Socks5ReplySuccess); err != nil {
			_ = conn.Close()

			return
		}
		h.logger.InfoContext(ctx, "[", name, "] inbound connection to ", destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
	case constant.Socks5UDPAssociateCmd:
		if err := reply(conn, constant.Socks5ReplySuccess); err != nil {
			_ = conn.Close()

			return
		}
		h.logger.InfoContext(ctx, "[", name, "] inbound packet connection")
		h.router.RoutePacketConnectionEx(ctx, newPacketConn(conn), metadata, onClose)
	default:
		_ = reply(conn, constant.Socks5ReplyCommandNotSupported)
		_ = conn.Close()
	}
}

func reply(conn net.Conn, code byte) error {
	return model.WriteSocks5Response(conn, code, model.AddrSpec{IP: net.IPv4zero, Port: 0})
}

func toSocksaddr(a model.AddrSpec) M.Socksaddr {
	if a.FQDN != "" {
		return M.Socksaddr{Fqdn: a.FQDN, Port: uint16(a.Port)}
	}

	return M.SocksaddrFromNet(&net.TCPAddr{IP: a.IP, Port: a.Port}).Unwrap()
}

// session forgets itself when closed, so a router that never calls onClose
// cannot leak entries.
type session struct {
	net.Conn
	h *Inbound
}

func (s *session) Close() error {
	s.h.untrack(s)

	return s.Conn.Close()
}
