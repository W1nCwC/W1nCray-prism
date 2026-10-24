// Package hot holds the glue the hot-update inbounds share: the routing
// metadata of an accepted connection and the stable-id admission check.
//
// The inbounds of this program are derived from the upstream inbounds of the
// upstream core project (GPL-3.0-or-later); see NOTICE.
package hot

import (
	"context"
	"net"
	"os"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// Updater is implemented by every inbound that serves panel users.
type Updater interface {
	// UpdateUsers replaces the user set; ids are stable panel user ids.
	UpdateUsers(users []gate.User) error
}

// Base is embedded by the index-keyed (QUIC) inbounds: the service reports the
// stable panel user id in the context and Base routes the connection.
type Base struct {
	inbound.Adapter
	Gate      *gate.Gate
	Router    adapter.ConnectionRouterEx
	Logger    log.ContextLogger
	Listener  *listener.Listener
	TLSConfig tls.ServerConfig
}

func (b *Base) metadata(source, destination M.Socksaddr) adapter.InboundContext {
	var metadata adapter.InboundContext
	metadata.Inbound = b.Tag()
	metadata.InboundType = b.Type()
	//nolint:staticcheck
	metadata.InboundDetour = b.Listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = b.Listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination

	return metadata
}

// NewConnectionEx implements N.TCPConnectionHandlerEx.
func (b *Base) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	userID, _ := auth.UserFromContext[int](ctx)
	if !b.Gate.Known(b.Tag(), userID) {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	metadata := b.metadata(source, destination)
	metadata.User = strconv.Itoa(userID)
	b.Logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	b.Router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// NewPacketConnectionEx implements N.UDPConnectionHandlerEx.
func (b *Base) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	userID, _ := auth.UserFromContext[int](ctx)
	if !b.Gate.Known(b.Tag(), userID) {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)

		return
	}
	metadata := b.metadata(source, destination)
	metadata.User = strconv.Itoa(userID)
	b.Logger.InfoContext(ctx, "[", metadata.User, "] inbound packet connection to ", metadata.Destination)
	b.Router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// StartUDP starts the TLS config and binds the UDP listener; start hands the
// packet conn to the protocol service and closer stops it.
func (b *Base) StartUDP(stage adapter.StartStage, scope *adapter.Scope, start func(net.PacketConn) error, closer func() error) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if b.TLSConfig != nil {
		if err := b.TLSConfig.Start(); err != nil {
			return err
		}
		scope.Add(b.TLSConfig.Close)
	}
	packetConn, err := b.Listener.ListenUDP()
	if err != nil {
		return err
	}
	scope.Add(b.Listener.Close)
	if err := start(packetConn); err != nil {
		return err
	}
	scope.Add(closer)

	return nil
}
