//go:build ignore

// mieruclient is a throwaway test client for the lab: it opens one mieru
// tunnel with the official client library, does a single HTTP GET through it
// and prints a one-line result. It is not shipped.
//
//	mieruclient -server host:port -user U -pass P -transport tcp -url http://target/path
//	mieruclient -server host -ports 20000-20100 -user U -pass P -transport udp -url http://target/path
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	apiclient "github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func fail(format string, a ...any) {
	fmt.Printf("ERR "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: mieruclient -server host:port [-ports lo-hi] -user U -pass P -transport tcp|udp [-pattern <base64>] -url http://target/path [-range-bytes N]

  -server       mieru server address host:port (with -ports only the host is used)
  -ports        port range lo-hi, bound as a PortRange instead of a single port
  -user, -pass  mieru user credentials
  -transport    tcp (default) or udp
  -pattern      base64 traffic pattern (as in the panel's traffic_pattern)
  -url          http:// target fetched through the tunnel (GET)
  -range-bytes  if > 0, send "Range: bytes=0-(N-1)"
  timeout is 30s; prints "OK status=<code> bytes=<n> md5=<hex>" or "ERR <reason>" (exit 1)`)
	}
	server := flag.String("server", "", "host:port")
	ports := flag.String("ports", "", "lo-hi")
	user := flag.String("user", "", "user")
	pass := flag.String("pass", "", "password")
	transport := flag.String("transport", "tcp", "tcp|udp")
	pattern := flag.String("pattern", "", "base64 traffic pattern")
	target := flag.String("url", "", "target url")
	rangeBytes := flag.Int64("range-bytes", 0, "Range bytes")
	flag.Parse()
	if *server == "" || *user == "" || *pass == "" || *target == "" {
		flag.Usage()
		os.Exit(2)
	}

	var tp appctlpb.TransportProtocol
	switch *transport {
	case "tcp":
		tp = appctlpb.TransportProtocol_TCP
	case "udp":
		tp = appctlpb.TransportProtocol_UDP
	default:
		fail("bad -transport %q", *transport)
	}

	host, portText, err := net.SplitHostPort(*server)
	if err != nil {
		if *ports == "" {
			fail("bad -server: %v", err)
		}
		host, portText = *server, ""
	}
	binding := &appctlpb.PortBinding{Protocol: tp.Enum()}
	if *ports != "" {
		binding.PortRange = proto.String(*ports)
	} else {
		p, err := strconv.Atoi(portText)
		if err != nil {
			fail("bad port: %v", err)
		}
		binding.Port = proto.Int32(int32(p))
	}

	profile := &appctlpb.ClientProfile{
		ProfileName: proto.String("t"),
		User:        &appctlpb.User{Name: proto.String(*user), Password: proto.String(*pass)},
		Servers:     []*appctlpb.ServerEndpoint{{IpAddress: proto.String(host), PortBindings: []*appctlpb.PortBinding{binding}}},
	}
	if *pattern != "" {
		p, err := trafficpattern.Decode(*pattern)
		if err != nil {
			fail("bad -pattern: %v", err)
		}
		profile.TrafficPattern = p
	}

	u, err := url.Parse(*target)
	if err != nil || u.Host == "" {
		fail("bad -url")
	}
	dest := u.Host
	if u.Port() == "" {
		dest = net.JoinHostPort(u.Hostname(), "80")
	}

	c := apiclient.NewClient()
	if err := c.Store(&apiclient.ClientConfig{Profile: profile}); err != nil {
		fail("client store: %v", err)
	}
	if err := c.Start(); err != nil {
		fail("client start: %v", err)
	}
	defer c.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var s model.NetAddrSpec
		if err := s.AddrSpec.From(dest); err != nil {
			return nil, err
		}
		s.Net = "tcp"

		return c.DialContext(ctx, s)
	}
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true, Proxy: nil}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *target, nil)
	if err != nil {
		fail("%v", err)
	}
	if *rangeBytes > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", *rangeBytes-1))
	}
	resp, err := cl.Do(req)
	if err != nil {
		fail("%v", err)
	}
	defer resp.Body.Close()
	h := md5.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		fail("read body after %d bytes: %v", n, err)
	}
	fmt.Printf("OK status=%d bytes=%d md5=%s\n", resp.StatusCode, n, hex.EncodeToString(h.Sum(nil)))
}
