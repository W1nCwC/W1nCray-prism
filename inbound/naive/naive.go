// Package naive is the NaiveProxy inbound (HTTP/2 CONNECT with padding) with
// hot user replacement, derived from the upstream core package protocol/naive
// (GPL-3.0-or-later). Only the TCP (HTTP/1.1 and HTTP/2) listener is offered.
// The user name of a client is the stable panel user id, the password is the
// user's uuid.
package naive

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// WrapError lets a build wrap HTTP/2 stream errors; nil keeps them as they are.
var WrapError func(error) error

func Register(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, New)
}

type Inbound struct {
	inbound.Adapter
	ctx        context.Context
	gate       *gate.Gate
	router     adapter.ConnectionRouterEx
	logger     logger.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	httpServer *http.Server
	users      atomic.Pointer[map[string]string] // stable id (decimal) => uuid
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) > 0 {
		return nil, E.New("users travel over the IPC, not in the config")
	}
	if options.Network != "" && common.Contains(options.Network.Build(), N.NetworkUDP) {
		return nil, E.New("naive over QUIC is not offered by this program (network must be tcp)")
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		gate:    gate.From(ctx),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
	}
	empty := map[string]string{}
	h.users.Store(&empty)
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}

	return h, nil
}

// UpdateUsers replaces the user set (HTTP basic credentials id:uuid).
func (n *Inbound) UpdateUsers(users []gate.User) error {
	next := make(map[string]string, len(users))
	for _, u := range users {
		next[strconv.Itoa(u.ID)] = u.UUID
	}
	n.users.Store(&next)

	return nil
}

func (n *Inbound) verify(name, password string) bool {
	want, ok := (*n.users.Load())[name]
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(want), []byte(password)) == 1
}

func (n *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if n.tlsConfig != nil {
		if err := n.tlsConfig.Start(); err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(n.tlsConfig.Close)
	}
	scope.Add(n.listener.Close)
	tcpListener, err := n.listener.ListenTCP()
	if err != nil {
		return err
	}
	n.httpServer = &http.Server{
		//nolint:staticcheck
		Handler: h2c.NewHandler(n, &http2.Server{}),
		BaseContext: func(net.Listener) context.Context {
			return n.ctx
		},
	}
	ln := net.Listener(tcpListener)
	if n.tlsConfig != nil {
		if len(n.tlsConfig.NextProtos()) == 0 {
			n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
		}
		ln = aTLS.NewListener(tcpListener, n.tlsConfig)
	}
	go func() {
		if sErr := n.httpServer.Serve(ln); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			n.logger.Error("http server serve error: ", sErr)
		}
	}()
	scope.Add(n.httpServer.Close)

	return nil
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	if request.Method != "CONNECT" {
		rejectHTTP(writer, http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("not CONNECT request"))

		return
	} else if request.Header.Get("Padding") == "" {
		rejectHTTP(writer, http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("missing naive padding"))

		return
	}
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = n.verify(userName, password) && n.known(userName)
	}
	if !authOk {
		rejectHTTP(writer, http.StatusProxyAuthRequired)
		n.badRequest(ctx, request, E.New("authorization failed"))

		return
	}
	writer.Header().Set("Padding", generatePaddingHeader())
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()

	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	source := sHttp.SourceAddress(request)
	destination := M.ParseSocksaddr(hostPort).Unwrap()

	if hijacker, isHijacker := writer.(http.Hijacker); isHijacker {
		conn, reader, err := hijacker.Hijack()
		if err != nil {
			n.badRequest(ctx, request, E.New("hijack failed"))

			return
		}
		if cacheLen := reader.Reader.Buffered(); cacheLen > 0 {
			cache := buf.NewSize(cacheLen)
			if _, err = cache.ReadFullFrom(reader.Reader, cacheLen); err != nil {
				cache.Release()
				conn.Close()
				n.badRequest(ctx, request, E.Cause(err, "read cache"))

				return
			}
			conn = bufio.NewCachedConn(conn, cache)
		}
		n.newConnection(ctx, false, &naiveConn{Conn: conn}, userName, source, destination)
	} else {
		n.newConnection(ctx, true, &naiveH2Conn{
			reader:        request.Body,
			writer:        writer,
			flusher:       writer.(http.Flusher),
			remoteAddress: source,
		}, userName, source, destination)
	}
}

// known is the gate check: the user is still in the table of this inbound.
func (n *Inbound) known(name string) bool {
	_, ok := n.gate.KnownName(n.Tag(), name)

	return ok
}

func (n *Inbound) newConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
	n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		n.router.RouteConnectionEx(ctx, conn, metadata, nil)

		return
	}
	done := make(chan struct{})
	wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
	n.router.RouteConnectionEx(ctx, wrapper, metadata, N.OnceClose(func(error) {
		close(done)
	}))
	<-done
	wrapper.CloseWrapper()
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func rejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)

		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)

		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
