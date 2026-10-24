//go:build !with_wireguard

package engine

import "github.com/sagernet/sing-box/adapter/endpoint"

func registerWireGuard(*endpoint.Registry) {}
