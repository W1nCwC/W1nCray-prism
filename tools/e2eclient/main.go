//go:build ignore

// e2eclient is a throwaway test client for the lab: it speaks one of the Prism
// protocols as a panel user and exposes a local mixed (HTTP + SOCKS) proxy, so a
// plain curl can drive traffic through a real kernel. It is not shipped.
//
//	e2eclient -kind tuic -server 127.0.0.1:24443 -uuid <uuid> -listen 127.0.0.1:1081
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

func main() {
	kind := flag.String("kind", "tuic", "tuic | hysteria | hysteria2 | anytls")
	server := flag.String("server", "127.0.0.1:443", "host:port of the kernel")
	uuid := flag.String("uuid", "", "the panel user's uuid")
	listen := flag.String("listen", "127.0.0.1:1081", "local mixed proxy address")
	sni := flag.String("sni", "localhost", "TLS server name")
	flag.Parse()

	host, portText, ok := strings.Cut(*server, ":")
	port, err := strconv.Atoi(portText)
	if !ok || err != nil || *uuid == "" {
		fmt.Fprintln(os.Stderr, "usage: e2eclient -kind K -server host:port -uuid U [-listen addr]")
		os.Exit(2)
	}
	lhost, lportText, _ := strings.Cut(*listen, ":")
	lport, _ := strconv.Atoi(lportText)

	tlsOut := func(alpn string) string {
		a := ""
		if alpn != "" {
			a = fmt.Sprintf(`,"alpn":["%s"]`, alpn)
		}
		return fmt.Sprintf(`"tls":{"enabled":true,"insecure":true,"server_name":"%s"%s}`, *sni, a)
	}
	srv := fmt.Sprintf(`"tag":"out","server":"%s","server_port":%d`, host, port)
	var outbound string
	switch *kind {
	case "tuic":
		outbound = fmt.Sprintf(`{"type":"tuic",%s,"uuid":"%s","password":"%s","congestion_control":"bbr",%s}`, srv, *uuid, *uuid, tlsOut("h3"))
	case "hysteria":
		outbound = fmt.Sprintf(`{"type":"hysteria",%s,"up_mbps":100,"down_mbps":100,"auth_str":"%s",%s}`, srv, *uuid, tlsOut("hysteria"))
	case "hysteria2":
		outbound = fmt.Sprintf(`{"type":"hysteria2",%s,"password":"%s",%s}`, srv, *uuid, tlsOut("h3"))
	case "anytls":
		outbound = fmt.Sprintf(`{"type":"anytls",%s,"password":"%s",%s}`, srv, *uuid, tlsOut(""))
	default:
		fmt.Fprintln(os.Stderr, "unknown kind", *kind)
		os.Exit(2)
	}
	cfg := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"mixed","tag":"in","listen":"%s","listen_port":%d}],"outbounds":[%s],"route":{"final":"out"}}`, lhost, lport, outbound)

	ctx := include.Context(context.Background())
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		fmt.Fprintln(os.Stderr, "box:", err)
		os.Exit(1)
	}
	if err := b.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	fmt.Println("e2eclient ready on", *listen)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = b.Close()
}
