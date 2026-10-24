package hysteria

import (
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
)

// buildQUICOptions maps the inbound options, including the deprecated Hysteria
// v1 window names, to the QUIC options of the service.
func buildQUICOptions(options option.HysteriaInboundOptions) qtls.QUICOptions {
	quicOptions := qtls.QUICOptions{
		IdleTimeout:             options.IdleTimeout.Build(),
		KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
		StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
		ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
		MaxConcurrentStreams:    options.MaxConcurrentStreams,
		InitialPacketSize:       options.InitialPacketSize,
		DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
	}
	if quicOptions.ConnectionReceiveWindow == 0 {
		quicOptions.ConnectionReceiveWindow = options.ReceiveWindowConn //nolint:staticcheck
	}
	if quicOptions.StreamReceiveWindow == 0 {
		quicOptions.StreamReceiveWindow = options.ReceiveWindowClient //nolint:staticcheck
	}
	if quicOptions.MaxConcurrentStreams == 0 {
		quicOptions.MaxConcurrentStreams = options.MaxConnClient //nolint:staticcheck
	}
	if !quicOptions.DisablePathMTUDiscovery {
		quicOptions.DisablePathMTUDiscovery = options.DisableMTUDiscovery //nolint:staticcheck
	}

	return quicOptions
}
