package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	apiclient "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// ---- config -----------------------------------------------------------------

func mieruInbound(tag string, port int, transport, pattern string) string {
	s := fmt.Sprintf(`{"type":"mieru","tag":"%s","listen":"127.0.0.1","listen_port":%d`, tag, port)
	if transport != "" {
		s += fmt.Sprintf(`,"transport":"%s"`, transport)
	}
	if pattern != "" {
		s += fmt.Sprintf(`,"traffic_pattern":"%s"`, pattern)
	}

	return s + `}`
}

func patternB64(t *testing.T, seed int32, unlock bool) string {
	t.Helper()
	enc := trafficpattern.Encode(&appctlpb.TrafficPattern{Seed: proto.Int32(seed), UnlockAll: proto.Bool(unlock)})
	if enc == "" {
		t.Fatal("encode traffic pattern")
	}

	return enc
}

// ---- client (the library's own client API, tests only) ------------------------

func mieruClient(t *testing.T, port int, udp bool, user, password, pattern string) apiclient.Client {
	t.Helper()
	transport := appctlpb.TransportProtocol_TCP
	if udp {
		transport = appctlpb.TransportProtocol_UDP
	}
	profile := &appctlpb.ClientProfile{
		ProfileName: proto.String("t"),
		User:        &appctlpb.User{Name: proto.String(user), Password: proto.String(password)},
		Servers: []*appctlpb.ServerEndpoint{{
			IpAddress:    proto.String("127.0.0.1"),
			PortBindings: []*appctlpb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: transport.Enum()}},
		}},
	}
	if pattern != "" {
		p, err := trafficpattern.Decode(pattern)
		if err != nil {
			t.Fatal(err)
		}
		profile.TrafficPattern = p
	}
	c := apiclient.NewClient()
	if err := c.Store(&apiclient.ClientConfig{Profile: profile}); err != nil {
		t.Fatalf("client store: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })

	return c
}

func netSpec(t *testing.T, network, addr string) model.NetAddrSpec {
	t.Helper()
	var s model.NetAddrSpec
	if err := s.AddrSpec.From(addr); err != nil {
		t.Fatal(err)
	}
	s.Net = network

	return s
}

// mieruFetch downloads n bytes from target (an https test server URL) through c.
func mieruFetch(c apiclient.Client, target string, n int, slow time.Duration) (int64, error) {
	host := strings.TrimPrefix(target, "https://")
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var s model.NetAddrSpec
		if err := s.AddrSpec.From(host); err != nil {
			return nil, err
		}
		s.Net = "tcp"
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		return c.DialContext(ctx, s)
	}
	tr := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := cl.Get(fmt.Sprintf("%s/bytes?n=%d&slow=%d", target, n, slow.Milliseconds()))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	got, err := io.Copy(io.Discard, resp.Body)
	if err == nil && got != int64(n) {
		err = fmt.Errorf("short body %d/%d", got, n)
	}

	return got, err
}

func goMieruFetch(c apiclient.Client, target string, n int, slow time.Duration) chan fetchResult {
	ch := make(chan fetchResult, 1)
	go func() {
		g, e := mieruFetch(c, target, n, slow)
		ch <- fetchResult{g, e}
	}()

	return ch
}

// udpRoundTrip sends datagrams through a UDP ASSOCIATE session to an echo
// server and expects them back.
func udpRoundTrip(t *testing.T, c apiclient.Client, echo *net.UDPConn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, netSpec(t, "udp", echo.LocalAddr().String()))
	if err != nil {
		return err
	}
	defer conn.Close()
	pc := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))
	dst := echo.LocalAddr().(*net.UDPAddr)
	for i := 0; i < 3; i++ {
		msg := []byte("ping-" + strconv.Itoa(i))
		if _, err := pc.WriteTo(msg, dst); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if string(buf[:n]) != string(msg) || from.(*net.UDPAddr).Port != dst.Port {
			return fmt.Errorf("echo mismatch: %q from %v", buf[:n], from)
		}
	}

	return nil
}

func newEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := l.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = l.WriteToUDP(buf[:n], a)
		}
	}()

	return l
}

func trafficOf(t *testing.T, v *env, tag string, id int) int64 {
	t.Helper()
	_, traffic, _, ok := v.g.Snapshot(tag)
	if !ok {
		t.Fatalf("%s: no snapshot", tag)
	}
	var sum int64
	for _, tr := range traffic {
		if tr.ID != id {
			t.Fatalf("%s: traffic of unexpected user %d", tag, tr.ID)
		}
		sum += tr.Up + tr.Down
	}

	return sum
}

var mieruTransports = []struct {
	name string
	udp  bool
}{{"tcp", false}, {"udp", true}}

// ---- tests ------------------------------------------------------------------

func TestMieruCarriesTrafficAndCountsIt(t *testing.T) {
	for _, tc := range mieruTransports {
		t.Run(tc.name, func(t *testing.T) {
			v := newEnv(t)
			port := freePort(t)
			// The server pattern differs from the client's on purpose.
			if err := v.apply("h1", serverConfig(mieruInbound("in", port, tc.name, patternB64(t, 7, true)))); err != nil {
				t.Fatalf("apply: %v", err)
			}
			// The inbound started without users; the first update must take effect.
			v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
			c := mieruClient(t, port, tc.udp, "1001", uuidA, patternB64(t, 99, false))

			got, err := mieruFetch(c, v.target.URL, mib, 0)
			if err != nil || got != mib {
				t.Fatalf("got=%d err=%v", got, err)
			}
			// The last write may be counted a moment after the client has the data.
			var sum int64
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
				if sum = trafficOf(t, v, "in", 1001); sum >= mib {
					break
				}
			}
			if sum < mib {
				t.Fatalf("counted %d bytes, want >= %d", sum, mib)
			}
			if err := udpRoundTrip(t, c, newEcho(t)); err != nil {
				t.Fatalf("udp associate: %v", err)
			}
		})
	}
}

func TestMieruRefusesUnknownAndWrongUsers(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(mieruInbound("in", port, "", ""))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
	if _, err := mieruFetch(mieruClient(t, port, false, "1002", uuidB, ""), v.target.URL, 1024, 0); err == nil {
		t.Fatal("unknown user 1002 was served")
	}
	if _, err := mieruFetch(mieruClient(t, port, false, "1001", uuidB, ""), v.target.URL, 1024, 0); err == nil {
		t.Fatal("a wrong password was served")
	}
	if _, err := mieruFetch(mieruClient(t, port, false, "1001", uuidA, ""), v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the real user was refused: %v", err)
	}
}

func TestMieruHotAddRemoveKicks(t *testing.T) {
	for _, tc := range mieruTransports {
		t.Run(tc.name, func(t *testing.T) {
			v := newEnv(t)
			port := freePort(t)
			if err := v.apply("h1", serverConfig(mieruInbound("in", port, tc.name, ""))); err != nil {
				t.Fatal(err)
			}
			v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
			a := mieruClient(t, port, tc.udp, "1001", uuidA, "")

			if _, err := mieruFetch(mieruClient(t, port, tc.udp, "1002", uuidB, ""), v.target.URL, 1024, 0); err == nil {
				t.Fatal("unknown user 1002 was served")
			}

			// A slow download of 1001 spans the addition of 1002.
			slow := goMieruFetch(a, v.target.URL, mib, 3*time.Second)
			time.Sleep(800 * time.Millisecond)
			v.setUsers("in", 2, gate.User{ID: 1001, UUID: uuidA}, gate.User{ID: 1002, UUID: uuidB})
			b := mieruClient(t, port, tc.udp, "1002", uuidB, "")
			if _, err := mieruFetch(b, v.target.URL, 1024, 0); err != nil {
				t.Fatalf("new user 1002 refused after the update: %v", err)
			}
			if r := <-slow; r.err != nil {
				t.Fatalf("in-flight 1001 download broke on the update: %v", r.err)
			}

			// Remove 1001 while it downloads: the session is kicked.
			slow = goMieruFetch(a, v.target.URL, mib, 3*time.Second)
			time.Sleep(800 * time.Millisecond)
			_, removed, kicked, _, err := v.e.SetUsers("in", 3, []gate.User{{ID: 1002, UUID: uuidB}})
			if err != nil || removed != 1 {
				t.Fatalf("remove: removed=%d err=%v", removed, err)
			}
			if r := <-slow; r.err == nil {
				t.Fatalf("a removed user finished its download (kicked=%d)", kicked)
			}
			if _, err := mieruFetch(a, v.target.URL, 1024, 0); err == nil {
				t.Fatal("removed user 1001 was served afterwards")
			}
			if _, err := mieruFetch(b, v.target.URL, 1024, 0); err != nil {
				t.Fatalf("remaining user 1002 was disturbed: %v", err)
			}
		})
	}
}

func TestMieruConfigChangeClosesOldSessions(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("h1", serverConfig(mieruInbound("in", port, "", ""))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
	a := mieruClient(t, port, false, "1001", uuidA, "")
	if _, err := mieruFetch(a, v.target.URL, 1024, 0); err != nil {
		t.Fatal(err)
	}

	slow := goMieruFetch(a, v.target.URL, mib, 8*time.Second)
	time.Sleep(800 * time.Millisecond)
	start := time.Now()
	if err := v.apply("h2", serverConfig(mieruInbound("in", port, "", patternB64(t, 3, false)))); err != nil {
		t.Fatalf("apply h2: %v", err)
	}
	r := <-slow
	if r.err == nil {
		t.Fatal("the old session survived the config change")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("the old session was closed late (%v): %v", time.Since(start), r.err)
	}
	// The user table is kept; a fresh client is served by the new config.
	fresh := mieruClient(t, port, false, "1001", uuidA, "")
	if _, err := mieruFetch(fresh, v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the new config does not serve: %v", err)
	}
}

func TestMieruInvalidConfigKeepsTheRunningOne(t *testing.T) {
	v := newEnv(t)
	port := freePort(t)
	if err := v.apply("good", serverConfig(mieruInbound("in", port, "", ""))); err != nil {
		t.Fatal(err)
	}
	v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})
	c := mieruClient(t, port, false, "1001", uuidA, "")

	cases := map[string]string{
		"bad base64":      fmt.Sprintf(`"listen_port":%d,"traffic_pattern":"@@@not-base64@@@"`, port),
		"bad protobuf":    fmt.Sprintf(`"listen_port":%d,"traffic_pattern":"AAECAwQFBgcICQ=="`, port),
		"pattern too big": fmt.Sprintf(`"listen_port":%d,"traffic_pattern":"%s"`, port, strings.Repeat("A", 3000)),
		"users in cfg":    fmt.Sprintf(`"listen_port":%d,"users":[{"name":"1001","password":"p"}]`, port),
		"port range":      `"listen_port":"2000-2010"`,
		"bad transport":   fmt.Sprintf(`"listen_port":%d,"transport":"quic"`, port),
		"no port":         `"transport":"tcp"`,
	}
	for name, fields := range cases {
		cfg := `{"inbounds":[{"type":"mieru","tag":"in","listen":"127.0.0.1",` + fields + `}]}`
		_, err := v.e.Apply("bad-"+name, []byte(cfg))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err=%v, want ErrInvalid", name, err)
		}
	}
	s := v.e.Status()
	if s.ConfigHash == nil || *s.ConfigHash != "good" || s.RejectedHash == nil {
		t.Fatalf("status after a rejected config: %+v", s)
	}
	if _, err := mieruFetch(c, v.target.URL, 1024, 0); err != nil {
		t.Fatalf("the running config stopped serving: %v", err)
	}
}
