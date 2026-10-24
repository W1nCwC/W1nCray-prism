// Package tuic is the TUIC v5 inbound with hot user replacement, derived from
// the upstream core package protocol/tuic (GPL-3.0-or-later).
package tuic

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/W1nCwC/W1nCray-prism/gate"
	"github.com/W1nCwC/W1nCray-prism/inbound/hot"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.TUICInboundOptions](registry, C.TypeTUIC, New)
}

type Inbound struct {
	hot.Base
	server *tuic.Service[int]
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	h := &Inbound{Base: hot.Base{
		Adapter: inbound.NewAdapter(C.TypeTUIC, tag),
		Gate:    gate.From(ctx),
		Router:  uot.NewRouter(router, logger),
		Logger:  logger,
		Listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		TLSConfig: tlsConfig,
	}}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	service, err := tuic.NewService[int](tuic.ServiceOptions{
		Context:   ctx,
		Logger:    logger,
		TLSConfig: tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		CongestionControl: options.CongestionControl,
		AuthTimeout:       time.Duration(options.AuthTimeout),
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
		UDPTimeout:        udpTimeout,
		Handler:           h,
	})
	if err != nil {
		return nil, err
	}
	h.server = service

	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return h.StartUDP(stage, scope, h.server.Start, h.server.Close)
}

// UpdateUsers replaces the user set without touching the QUIC listener. The
// credentials of a user are its uuid, used as the uuid and as the password.
func (h *Inbound) UpdateUsers(users []gate.User) error {
	ids := make([]int, 0, len(users))
	uuids := make([][16]byte, 0, len(users))
	passwords := make([]string, 0, len(users))
	for _, u := range users {
		parsed, err := uuid.FromString(u.UUID)
		if err != nil {
			return E.Cause(err, "invalid uuid for user ", u.ID)
		}
		ids = append(ids, u.ID)
		uuids = append(uuids, parsed)
		passwords = append(passwords, u.UUID)
	}
	h.server.UpdateUsers(ids, uuids, passwords)

	return nil
}
