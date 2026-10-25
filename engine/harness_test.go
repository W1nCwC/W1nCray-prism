package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

const (
	uuidA = "b831381d-6324-4d53-ad4f-8cda48b30811"
	uuidB = "c6a2b1a3-1111-4c3e-9a4f-2f2b6f0a0002"
)

// ---- environment ------------------------------------------------------------

type env struct {
	t      *testing.T
	dir    string
	cert   string
	key    string
	target *httptest.Server
	g      *gate.Gate
	e      *Engine
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		slow, _ := strconv.Atoi(r.URL.Query().Get("slow"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := make([]byte, 16*1024)
		steps := (n + len(chunk) - 1) / len(chunk)
		for sent := 0; sent < n; {
			k := min(len(chunk), n-sent)
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			sent += k
			if slow > 0 {
				w.(http.Flusher).Flush()
				time.Sleep(time.Duration(slow) * time.Millisecond / time.Duration(steps))
			}
		}
	}))
	t.Cleanup(target.Close)
	g := gate.New()
	e, err := New(filepath.Join(dir, "state"), g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })

	return &env{t: t, dir: dir, cert: cert, key: key, target: target, g: g, e: e}
}

func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)

	return strings.ReplaceAll(cp, `\`, `/`), strings.ReplaceAll(kp, `\`, `/`)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

func (v *env) tls(alpn string) string {
	a := ""
	if alpn != "" {
		a = fmt.Sprintf(`,"alpn":["%s"]`, alpn)
	}

	return fmt.Sprintf(`"tls":{"enabled":true,"certificate_path":"%s","key_path":"%s"%s}`, v.cert, v.key, a)
}

// inbound returns the JSON of one server inbound.
func (v *env) inbound(kind, tag string, port int) string {
	base := fmt.Sprintf(`"tag":"%s","listen":"127.0.0.1","listen_port":%d`, tag, port)
	switch kind {
	case "tuic":
		return fmt.Sprintf(`{"type":"tuic",%s,"congestion_control":"bbr",%s}`, base, v.tls("h3"))
	case "hysteria":
		return fmt.Sprintf(`{"type":"hysteria",%s,"up_mbps":200,"down_mbps":200,%s}`, base, v.tls("hysteria"))
	case "hysteria2":
		return fmt.Sprintf(`{"type":"hysteria2",%s,%s}`, base, v.tls("h3"))
	case "anytls":
		return fmt.Sprintf(`{"type":"anytls",%s,%s}`, base, v.tls(""))
	case "naive":
		return fmt.Sprintf(`{"type":"naive",%s,"network":"tcp",%s}`, base, v.tls(""))
	case "vless":
		return fmt.Sprintf(`{"type":"vless",%s,%s}`, base, v.tls(""))
	case "vless-ws":
		return fmt.Sprintf(`{"type":"vless",%s,%s,"transport":{"type":"ws","path":"/ws"}}`, base, v.tls(""))
	case "vless-vision":
		return fmt.Sprintf(`{"type":"vless",%s,"users":[{"flow":"xtls-rprx-vision"}],%s}`, base, v.tls(""))
	case "vless-mux":
		return fmt.Sprintf(`{"type":"vless",%s,%s,"multiplex":{"enabled":true}}`, base, v.tls(""))
	case "trojan":
		return fmt.Sprintf(`{"type":"trojan",%s,%s}`, base, v.tls(""))
	case "trojan-ws":
		return fmt.Sprintf(`{"type":"trojan",%s,%s,"transport":{"type":"ws","path":"/ws"}}`, base, v.tls(""))
	}
	v.t.Fatalf("unknown kind %s", kind)

	return ""
}

func serverConfig(inbounds ...string) string {
	return `{"log":{"level":"error"},"inbounds":[` + strings.Join(inbounds, ",") + `],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
}

func (v *env) apply(hash, cfg string) error {
	_, err := v.e.Apply(hash, []byte(cfg))

	return err
}

func (v *env) setUsers(tag string, seq int64, users ...gate.User) {
	v.t.Helper()
	if _, _, _, _, err := v.e.SetUsers(tag, seq, users); err != nil {
		v.t.Fatalf("SetUsers(%s): %v", tag, err)
	}
}

// ---- client side ------------------------------------------------------------

func tlsOut(alpn string) string {
	a := ""
	if alpn != "" {
		a = fmt.Sprintf(`,"alpn":["%s"]`, alpn)
	}

	return fmt.Sprintf(`"tls":{"enabled":true,"insecure":true,"server_name":"localhost"%s}`, a)
}

// outbound returns the client outbound JSON that talks to a server inbound as
// the user with the given uuid.
func clientOutbound(kind, tag string, port int, uuid string) string {
	srv := fmt.Sprintf(`"tag":"%s","server":"127.0.0.1","server_port":%d`, tag, port)
	switch kind {
	case "tuic":
		return fmt.Sprintf(`{"type":"tuic",%s,"uuid":"%s","password":"%s","congestion_control":"bbr",%s}`, srv, uuid, uuid, tlsOut("h3"))
	case "hysteria":
		return fmt.Sprintf(`{"type":"hysteria",%s,"up_mbps":200,"down_mbps":200,"auth_str":"%s",%s}`, srv, uuid, tlsOut("hysteria"))
	case "hysteria2":
		return fmt.Sprintf(`{"type":"hysteria2",%s,"password":"%s",%s}`, srv, uuid, tlsOut("h3"))
	case "anytls":
		return fmt.Sprintf(`{"type":"anytls",%s,"password":"%s",%s}`, srv, uuid, tlsOut(""))
	case "vless":
		return fmt.Sprintf(`{"type":"vless",%s,"uuid":"%s",%s}`, srv, uuid, tlsOut(""))
	case "vless-ws":
		return fmt.Sprintf(`{"type":"vless",%s,"uuid":"%s",%s,"transport":{"type":"ws","path":"/ws"}}`, srv, uuid, tlsOut(""))
	case "vless-vision":
		return fmt.Sprintf(`{"type":"vless",%s,"uuid":"%s","flow":"xtls-rprx-vision",%s}`, srv, uuid, tlsOut(""))
	case "vless-mux":
		return fmt.Sprintf(`{"type":"vless",%s,"uuid":"%s",%s,"multiplex":{"enabled":true}}`, srv, uuid, tlsOut(""))
	case "trojan":
		return fmt.Sprintf(`{"type":"trojan",%s,"password":"%s",%s}`, srv, uuid, tlsOut(""))
	case "trojan-ws":
		return fmt.Sprintf(`{"type":"trojan",%s,"password":"%s",%s,"transport":{"type":"ws","path":"/ws"}}`, srv, uuid, tlsOut(""))
	}

	return ""
}

type client struct {
	b     *box.Box
	ports map[string]int
}

// newClient starts a stock client with one mixed inbound per outbound.
func newClient(t *testing.T, outbounds map[string]string) *client {
	t.Helper()
	c := &client{ports: map[string]int{}}
	var ins, outs, rules []string
	for key, out := range outbounds {
		port := freePort(t)
		c.ports[key] = port
		ins = append(ins, fmt.Sprintf(`{"type":"mixed","tag":"c-%s","listen":"127.0.0.1","listen_port":%d}`, key, port))
		outs = append(outs, out)
		rules = append(rules, fmt.Sprintf(`{"inbound":["c-%s"],"outbound":"%s"}`, key, tagOf(out)))
	}
	cfg := `{"log":{"level":"error"},"inbounds":[` + strings.Join(ins, ",") + `],"outbounds":[` + strings.Join(outs, ",") +
		`,{"type":"direct","tag":"direct"}],"route":{"rules":[` + strings.Join(rules, ",") + `]}}`
	ctx := include.Context(context.Background())
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(cfg))
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("client box: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	c.b = b

	return c
}

func tagOf(out string) string {
	i := strings.Index(out, `"tag":"`)
	rest := out[i+7:]

	return rest[:strings.Index(rest, `"`)]
}

func (c *client) proxy(key string) string { return fmt.Sprintf("http://127.0.0.1:%d", c.ports[key]) }

// fetch downloads n bytes through proxy; slow spreads the body over that duration.
func fetch(proxy, target string, n int, slow time.Duration) (int64, error) {
	pu, _ := url.Parse(proxy)
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
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

// ---- minimal naive client ----------------------------------------------------

const naivePaddingCount = 8

type naiveClientConn struct {
	net.Conn
	r                                   io.Reader
	readPad, writePad, readRem, padSkip int
}

func (c *naiveClientConn) Read(b []byte) (int, error) {
	if c.readRem > 0 {
		if len(b) > c.readRem {
			b = b[:c.readRem]
		}
		n, err := c.r.Read(b)
		c.readRem -= n

		return n, err
	}
	if c.padSkip > 0 {
		if _, err := io.CopyN(io.Discard, c.r, int64(c.padSkip)); err != nil {
			return 0, err
		}
		c.padSkip = 0
	}
	if c.readPad < naivePaddingCount {
		var h [3]byte
		if _, err := io.ReadFull(c.r, h[:]); err != nil {
			return 0, err
		}
		c.readPad++
		c.readRem, c.padSkip = int(binary.BigEndian.Uint16(h[:2])), int(h[2])

		return c.Read(b)
	}

	return c.r.Read(b)
}

func (c *naiveClientConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		if c.writePad >= naivePaddingCount {
			n, err := c.Conn.Write(b)

			return total + n, err
		}
		chunk := b
		if len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		pad := mrand.Intn(256)
		frame := make([]byte, 3+len(chunk)+pad)
		binary.BigEndian.PutUint16(frame, uint16(len(chunk)))
		frame[2] = byte(pad)
		copy(frame[3:], chunk)
		if _, err := c.Conn.Write(frame); err != nil {
			return total, err
		}
		c.writePad++
		total += len(chunk)
		b = b[len(chunk):]
	}

	return total, nil
}

func naiveFetch(server, user, pass, target string, n int, slow time.Duration) (int64, error) {
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"http/1.1"}}}
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
