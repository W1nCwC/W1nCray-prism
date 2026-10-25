// Package vless is the VLESS inbound with hot user replacement, derived from the
// upstream core package protocol/vless (GPL-3.0-or-later). The service is keyed by
// the stable panel user id; the user's uuid is its credential.
//
// The flow is a property of the node, not of a user: the panel sets it for the
// whole inbound. It travels in the config as the only entry of "users"
// (`"users":[{"flow":"xtls-rprx-vision"}]`, name and uuid stay empty); real
// users arrive over the IPC.
package vless

import (
	"context"
	"net"
	"os"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.VLESSInboundOptions](registry, C.TypeVLESS, New)
}

type Inbound struct {
	inbound.Adapter
	gate      *gate.Gate
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *vless.Service[int]
	flow      string
	tlsConfig tls.ServerConfig
	transport adapter.V2RayServerTransport
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSInboundOptions) (adapter.Inbound, error) {
	flow, err := nodeFlow(options.Users)
	if err != nil {
		return nil, err
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeVLESS, tag),
		gate:    gate.From(ctx),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		flow:    flow,
	}
	h.router, err = mux.NewRouterWithOptions(h.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	h.service = vless.NewService[int](logger, adapter.NewUpstreamContextHandler(h.newConnectionEx, h.newPacketConnectionEx))
	if options.TLS != nil && options.TLS.Enabled {
		h.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled && flow == "",
		})
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		h.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), h.tlsConfig, (*transportHandler)(h))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	h.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: h,
	})

	return h, nil
}

// nodeFlow reads the node-level flow out of the placeholder user.
func nodeFlow(users []option.VLESSUser) (string, error) {
	switch len(users) {
	case 0:
		return "", nil
	case 1:
		if users[0].Name != "" || users[0].UUID != "" {
			return "", E.New("users travel over the IPC, not in the config")
		}
		if f := users[0].Flow; f != "" && f != "xtls-rprx-vision" {
			return "", E.New("unsupported flow: ", f)
		}

		return users[0].Flow, nil
	default:
		return "", E.New("users travel over the IPC, not in the config")
	}
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	if h.transport == nil {
		if err := h.listener.Start(); err != nil {
			return err
		}
		scope.Add(h.listener.Close)

		return nil
	}
	scope.Add(h.transport.Close)
	scope.Add(h.listener.Close)
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			if sErr := h.transport.Serve(tcpListener); sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}

	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))

			return
		}
		conn = tlsConn
	}
	if err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

// UpdateUsers replaces the user set; the service names a user by its stable id.
func (h *Inbound) UpdateUsers(users []gate.User) error {
	ids := make([]int, 0, len(users))
	uuids := make([]string, 0, len(users))
	flows := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
		uuids = append(uuids, u.UUID)
		flows = append(flows, h.flow)
	}
	h.service.UpdateUsers(ids, uuids, flows)

	return nil
}

func (h *Inbound) admitted(ctx context.Context) (int, bool) {
	id, ok := auth.UserFromContext[int](ctx)
	if !ok || !h.gate.Known(h.Tag(), id) {
		return 0, false
	}

	return id, true
}

func (h *Inbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	id, ok := h.admitted(ctx)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = strconv.Itoa(id)
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	id, ok := h.admitted(ctx)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = strconv.Itoa(id)
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		h.logger.InfoContext(ctx, "[", metadata.User, "] inbound packet addr connection")
	} else {
		h.logger.InfoContext(ctx, "[", metadata.User, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

type transportHandler Inbound

func (h *transportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	(*Inbound)(h).NewConnection(ctx, conn, metadata, onClose)
}
