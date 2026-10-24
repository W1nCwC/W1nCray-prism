// Package hysteria is the Hysteria v1 inbound with hot user replacement,
// derived from the upstream core package protocol/hysteria (GPL-3.0-or-later).
package hysteria

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
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/W1nCwC/W1nCray-prism/gate"
	"github.com/W1nCwC/W1nCray-prism/inbound/hot"
)

func Register(registry *inbound.Registry) {
	inbound.Register[option.HysteriaInboundOptions](registry, C.TypeHysteria, New)
}

type Inbound struct {
	hot.Base
	service *hysteria.Service[int]
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaInboundOptions) (adapter.Inbound, error) {
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
		Adapter: inbound.NewAdapter(C.TypeHysteria, tag),
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
	sendBps := uint64(options.UpMbps) * hysteria.MbpsToBps
	if options.Up.Value() > 0 {
		sendBps = options.Up.Value()
	}
	receiveBps := uint64(options.DownMbps) * hysteria.MbpsToBps
	if options.Down.Value() > 0 {
		receiveBps = options.Down.Value()
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	service, err := hysteria.NewService[int](hysteria.ServiceOptions{
		Context:       ctx,
		Logger:        logger,
		SendBPS:       sendBps,
		ReceiveBPS:    receiveBps,
		XPlusPassword: options.Obfs,
		TLSConfig:     tlsConfig,
		QUICOptions:   buildQUICOptions(options),
		UDPTimeout:    udpTimeout,
		Handler:       h,
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

// UpdateUsers replaces the user set; the auth string of a user is its uuid.
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
