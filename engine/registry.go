package engine

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"

	"github.com/W1nCwC/W1nCray-prism/inbound/anytls"
	"github.com/W1nCwC/W1nCray-prism/inbound/hysteria"
	"github.com/W1nCwC/W1nCray-prism/inbound/hysteria2"
	"github.com/W1nCwC/W1nCray-prism/inbound/naive"
	"github.com/W1nCwC/W1nCray-prism/inbound/tuic"
)

// newContext returns the registry context the core is built with. Only what a
// panel profile can ask for is registered, which keeps the binary small: the
// hot-update inbounds, and outbounds / DNS transports for routing.
func newContext() context.Context {
	in := inbound.NewRegistry()
	tuic.Register(in)
	hysteria.Register(in)
	hysteria2.Register(in)
	anytls.Register(in)
	naive.Register(in)

	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	block.RegisterOutbound(out)
	socks.RegisterOutbound(out)
	http.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	vmess.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	vless.RegisterOutbound(out)

	ep := endpoint.NewRegistry()
	registerWireGuard(ep)

	dnsReg := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsReg)
	transport.RegisterTCP(dnsReg)
	transport.RegisterTLS(dnsReg)
	transport.RegisterHTTPS(dnsReg)
	local.RegisterTransport(dnsReg)

	return box.Context(context.Background(), in, out, ep, dnsReg, service.NewRegistry(), certificate.NewRegistry())
}
