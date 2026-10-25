//go:build with_utls

package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// TestOutboundRealityThroughOwnRegistry sends upstream client -> engine B
// (anytls in, vless+reality+utls out) -> engine A (reality in) -> target. Both
// engines are built from Prism's own registry.
func TestOutboundRealityThroughOwnRegistry(t *testing.T) {
	a := newEnv(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(key.Bytes())
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	host, portText, _ := net.SplitHostPort(a.target.Listener.Addr().String())
	var targetPort int
	if _, err := fmt.Sscanf(portText, "%d", &targetPort); err != nil {
		t.Fatal(err)
	}
	portA := freePort(t)
	inA := fmt.Sprintf(`{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":%d,"users":[{"flow":"xtls-rprx-vision"}],`+
		`"tls":{"enabled":true,"server_name":"localhost","reality":{"enabled":true,"handshake":{"server":"%s","server_port":%d},"private_key":"%s","short_id":["abcd1234"]}}}`,
		portA, host, targetPort, private)
	if err := a.apply("hA", serverConfig(inA)); err != nil {
		t.Fatalf("apply A: %v", err)
	}
	a.setUsers("in", 1, gate.User{ID: 2001, UUID: uuidB})

	g2 := gate.New()
	e2, err := New(filepath.Join(t.TempDir(), "state"), g2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	b := &env{t: t, dir: a.dir, cert: a.cert, key: a.key, target: a.target, g: g2, e: e2}

	portB := freePort(t)
	cfgB := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[%s],"outbounds":[{"type":"vless","tag":"up","server":"127.0.0.1","server_port":%d,"uuid":"%s","flow":"xtls-rprx-vision",`+
		`"tls":{"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"%s","short_id":"abcd1234"}}}],"route":{"final":"up"}}`,
		b.inbound("anytls", "inb", portB), portA, uuidB, public)
	if err := b.apply("hB", cfgB); err != nil {
		t.Fatalf("apply B: %v", err)
	}
	b.setUsers("inb", 1, gate.User{ID: 1001, UUID: uuidA})

	c := newClient(t, map[string]string{"k": clientOutbound("anytls", "o-k", portB, uuidA)})
	got, err := fetch(c.proxy("k"), a.target.URL, mib, 0)
	if err != nil || got != mib {
		t.Fatalf("chain: got=%d err=%v", got, err)
	}
	if sum := sumTraffic(t, b, "inb", 1001); sum < mib {
		t.Fatalf("B counted %d bytes", sum)
	}
	if sum := sumTraffic(t, a, "in", 2001); sum < mib {
		t.Fatalf("A counted %d bytes", sum)
	}
}

func TestOutboundVlessTLSUtlsFirefoxIsAccepted(t *testing.T) {
	v := newEnv(t)
	cfg := `{"log":{"level":"error"},"inbounds":[],"outbounds":[{"type":"vless","tag":"up","server":"127.0.0.1","server_port":443,"uuid":"` + uuidA +
		`","tls":{"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"firefox"}}},{"type":"direct","tag":"direct"}],"route":{"final":"up"}}`
	if err := v.e.Check([]byte(cfg)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := v.apply("h1", cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}
