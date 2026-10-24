// Package anytls is the AnyTLS inbound with hot user replacement, derived from
// the upstream core package protocol/anytls (GPL-3.0-or-later). The user name of the service is
// the stable panel user id, the password is the user's uuid.
package anytls

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, New)
}

type Inbound struct {
	inbound.Adapter
	gate      *gate.Gate
	tlsConfig tls.ServerConfig
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *anytls.Service
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLS, tag),
		gate:    gate.From(ctx),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}
	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}
	service, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: paddingScheme,
		Handler:       (*handler)(h),
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	h.service = service
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
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(h.listener.Close)

	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
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
	list := make([]anytls.User, 0, len(users))
	for _, u := range users {
		list = append(list, anytls.User{Name: strconv.Itoa(u.ID), Password: u.UUID})
	}
	h.service.UpdateUsers(list)

	return nil
}

type handler Inbound

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	name, _ := auth.UserFromContext[string](ctx)
	if _, ok := h.gate.KnownName(h.Tag(), name); !ok {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	metadata.User = name
	h.logger.InfoContext(ctx, "[", name, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
