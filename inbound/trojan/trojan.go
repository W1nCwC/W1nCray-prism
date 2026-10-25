// Package trojan is the Trojan inbound with hot user replacement, derived from the
// upstream core package protocol/trojan (GPL-3.0-or-later). The service is keyed by
// the stable panel user id; the user's uuid is its password. Fallbacks are not
// offered (the panel has no field for them).
package trojan

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
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.TrojanInboundOptions](registry, C.TypeTrojan, New)
}

type Inbound struct {
	inbound.Adapter
	gate      *gate.Gate
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *trojan.Service[int]
	tlsConfig tls.ServerConfig
	transport adapter.V2RayServerTransport
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	if (options.Fallback != nil && options.Fallback.Server != "") || len(options.FallbackForALPN) > 0 {
		return nil, E.New("fallback is not offered by this program")
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTrojan, tag),
		gate:    gate.From(ctx),
		router:  router,
		logger:  logger,
	}
	var err error
	if options.TLS != nil && options.TLS.Enabled {
		h.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
	}
	h.service = trojan.NewService[int](adapter.NewUpstreamContextHandler(h.newConnection, h.newPacketConnection), nil, logger)
	if options.Transport != nil {
		h.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), h.tlsConfig, (*transportHandler)(h))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	h.router, err = mux.NewRouterWithOptions(h.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
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

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
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
	passwords := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
		passwords = append(passwords, u.UUID)
	}

	return h.service.UpdateUsers(ids, passwords)
}

func (h *Inbound) admitted(ctx context.Context) (int, bool) {
	id, ok := auth.UserFromContext[int](ctx)
	if !ok || !h.gate.Known(h.Tag(), id) {
		return 0, false
	}

	return id, true
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	id, ok := h.admitted(ctx)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = strconv.Itoa(id)
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound packet connection to ", metadata.Destination)
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
