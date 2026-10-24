// Package hysteria2 is the Hysteria 2 inbound with hot user replacement,
// derived from the upstream core package protocol/hysteria2 (GPL-3.0-or-later). Masquerade and
// realm are not offered: the panel never configures them.
package hysteria2

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/W1nCwC/W1nCray-prism/gate"
	"github.com/W1nCwC/W1nCray-prism/inbound/hot"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, New)
}

type Inbound struct {
	hot.Base
	service *hysteria2.Service[int]
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2InboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	if options.Masquerade != nil && options.Masquerade.Type != "" {
		return nil, E.New("masquerade is not offered by this program")
	}
	if options.Realm != nil {
		return nil, E.New("realm is not offered by this program")
	}
	var salamander string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		if options.Obfs.Type != hysteria2.ObfsTypeSalamander {
			return nil, E.New("obfs type ", options.Obfs.Type, " is not offered by this program")
		}
		salamander = options.Obfs.Password
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	h := &Inbound{Base: hot.Base{
		Adapter: inbound.NewAdapter(C.TypeHysteria2, tag),
		Gate:    gate.From(ctx),
		Router:  router,
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
	service, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:            ctx,
		Logger:             logger,
		BrutalDebug:        options.BrutalDebug,
		SendBPS:            uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamander,
		TLSConfig:          tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            udpTimeout,
		Handler:               h,
		BBRProfile:            options.BBRProfile,
	})
	if err != nil {
		return nil, err
	}
	h.service = service

	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return h.StartUDP(stage, scope, h.service.Start, h.service.Close)
}

// InterfaceUpdated drops the QUIC state after a network change.
func (h *Inbound) InterfaceUpdated(_ context.Context) {
	h.service.Reset()
}

// UpdateUsers replaces the user set; the password of a user is its uuid.
func (h *Inbound) UpdateUsers(users []gate.User) error {
	ids := make([]int, 0, len(users))
	secrets := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
		secrets = append(secrets, u.UUID)
	}
	h.service.UpdateUsers(ids, secrets)

	return nil
}
