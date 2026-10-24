//go:build with_wireguard

package engine

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

func registerWireGuard(registry *endpoint.Registry) { wireguard.RegisterEndpoint(registry) }
