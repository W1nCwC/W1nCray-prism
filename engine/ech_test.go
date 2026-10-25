//go:build with_quic && with_utls

package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	stls "github.com/sagernet/sing-box/common/tls"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// echPair is one generated ECH key pair in the forms the options take.
type echPair struct {
	keyLines    []string // server: PEM "ECH KEYS" block split into lines
	configLines []string // client: PEM "ECH CONFIGS" block split into lines
	configList  []byte   // raw ECHConfigList for the standard library client
}

func newECHPair(t *testing.T) echPair {
	t.Helper()
	cfgPem, keyPem, err := stls.ECHKeygenDefault("public.example.com")
	if err != nil {
		t.Fatalf("ECHKeygenDefault: %v", err)
	}
	blk, _ := pem.Decode([]byte(cfgPem))
	if blk == nil {
		t.Fatal("no ECH CONFIGS block")
	}
	split := func(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

	return echPair{keyLines: split(keyPem), configLines: split(cfgPem), configList: blk.Bytes}
}

func jsonLines(lines []string) string {
	b, _ := json.Marshal(lines)

	return string(b)
}

// withECHIn adds the ech block to the tls object of an inbound JSON.
func withECHIn(inbound string, p echPair) string {
	return strings.Replace(inbound, `"tls":{"enabled":true,`, `"tls":{"enabled":true,"ech":{"enabled":true,"key":`+jsonLines(p.keyLines)+`},`, 1)
}

// withECHOut adds the ech block to the tls object of a client outbound JSON.
func withECHOut(out string, p echPair) string {
	return strings.Replace(out, `"tls":{"enabled":true,`, `"tls":{"enabled":true,"ech":{"enabled":true,"config":`+jsonLines(p.configLines)+`},`, 1)
}

func sumTraffic(t *testing.T, v *env, tag string, id int64) int64 {
	t.Helper()
	_, traffic, _, ok := v.g.Snapshot(tag)
	if !ok {
		t.Fatalf("%s: no snapshot", tag)
	}
	var sum int64
	for _, tr := range traffic {
		if int64(tr.ID) != id {
			t.Fatalf("%s: traffic of unexpected user %d", tag, tr.ID)
		}
		sum += tr.Up + tr.Down
	}

	return sum
}

var echKinds = []string{"tuic", "hysteria", "hysteria2", "anytls", "vless", "trojan"}

func TestECHEveryProtocolCarriesTrafficAndCountsIt(t *testing.T) {
	for _, kind := range append(append([]string{}, echKinds...), "naive") {
		t.Run(kind, func(t *testing.T) {
			v := newEnv(t)
			p := newECHPair(t)
			port := freePort(t)
			if err := v.apply("h1", serverConfig(withECHIn(v.inbound(kind, "in", port), p))); err != nil {
				t.Fatalf("apply: %v", err)
			}
			v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})

			var got int64
			var err error
			if kind == "naive" {
				got, err = naiveECHFetch("127.0.0.1:"+strconv.Itoa(port), "1001", uuidA, v.target.URL, mib, p.configList)
			} else {
				c := newClient(t, map[string]string{"k": withECHOut(clientOutbound(kind, "o-k", port, uuidA), p)})
				got, err = fetch(c.proxy("k"), v.target.URL, mib, 0)
			}
			if err != nil || got != mib {
				t.Fatalf("%s with ECH: got=%d err=%v", kind, got, err)
			}
			if sum := sumTraffic(t, v, "in", 1001); sum < mib {
				t.Fatalf("%s: counted %d bytes, want >= %d", kind, sum, mib)
			}
		})
	}
}

// A client holding a different ECH config must not get through.
func TestECHWrongConfigIsRefused(t *testing.T) {
	for _, kind := range []string{"tuic", "hysteria2", "anytls", "vless", "trojan", "naive"} {
		t.Run(kind, func(t *testing.T) {
			v := newEnv(t)
			server, other := newECHPair(t), newECHPair(t)
			port := freePort(t)
			if err := v.apply("h1", serverConfig(withECHIn(v.inbound(kind, "in", port), server))); err != nil {
				t.Fatalf("apply: %v", err)
			}
			v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})

			var err error
			if kind == "naive" {
				_, err = naiveECHFetch("127.0.0.1:"+strconv.Itoa(port), "1001", uuidA, v.target.URL, 1024, other.configList)
			} else {
				c := newClient(t, map[string]string{"k": withECHOut(clientOutbound(kind, "o-k", port, uuidA), other)})
				_, err = fetch(c.proxy("k"), v.target.URL, 1024, 0)
			}
			if err == nil {
				t.Fatalf("%s: a client with the wrong ECH config was served", kind)
			}
			t.Logf("%s refused: %v", kind, err)
		})
	}
}

// Malformed ECH keys are rejected by Check and Apply, and the error does not
// echo the key material.
func TestECHMalformedKeyIsRejectedWithoutLeaking(t *testing.T) {
	v := newEnv(t)
	const marker = "SECRETKEYMARKER0123456789"
	bad := []string{"-----BEGIN ECH KEYS-----", marker, "-----END ECH KEYS-----"}
	for _, keys := range []string{jsonLines(bad), jsonLines([]string{marker})} {
		cfg := serverConfig(strings.Replace(v.inbound("anytls", "in", freePort(t)), `"tls":{"enabled":true,`, `"tls":{"enabled":true,"ech":{"enabled":true,"key":`+keys+`},`, 1))
		err := v.e.Check([]byte(cfg))
		if err == nil {
			t.Fatalf("Check accepted malformed ECH key %s", keys)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error leaks key content: %v", err)
		}
		t.Logf("Check error: %v", err)
		if err := v.apply("bad", cfg); err == nil {
			t.Fatal("Apply accepted malformed ECH key")
		} else if strings.Contains(err.Error(), marker) {
			t.Fatalf("Apply error leaks key content: %v", err)
		}
	}
}

// naiveECHFetch is the stock naive client with an ECH config list; Go's TLS
// client requires TLS 1.3 for that.
func naiveECHFetch(server, user, pass, target string, n int, configList []byte) (int64, error) {
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{
			InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: configList,
		}}
		raw, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, err
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nPadding: %s\r\n\r\n",
			addr, addr, cred, "!#$()+<>?@[]^`{}~~~~~~~~~~~~~~~~~~")
		br := bufio.NewReader(raw)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			raw.Close()

			return nil, err
		}
		if resp.StatusCode != 200 {
			raw.Close()

			return nil, fmt.Errorf("naive CONNECT: %s", resp.Status)
		}
		_ = raw.SetDeadline(time.Time{})

		return &naiveClientConn{Conn: raw, r: br}, nil
	}
	tr := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := cl.Get(fmt.Sprintf("%s/bytes?n=%d&slow=0", target, n))
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
