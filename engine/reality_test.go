//go:build with_utls

package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// TestVlessRealityCarriesTrafficAndCountsIt serves VLESS behind Reality with a
// local TLS 1.3 server as the handshake target, and drives it with a stock
// client using the matching public key.
func TestVlessRealityCarriesTrafficAndCountsIt(t *testing.T) {
	v := newEnv(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(key.Bytes())
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	host, portText, _ := net.SplitHostPort(v.target.Listener.Addr().String())
	var targetPort int
	if _, err := fmt.Sscanf(portText, "%d", &targetPort); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	inbound := fmt.Sprintf(`{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":%d,"users":[{"flow":"xtls-rprx-vision"}],`+
		`"tls":{"enabled":true,"server_name":"localhost","reality":{"enabled":true,"handshake":{"server":"%s","server_port":%d},"private_key":"%s","short_id":["abcd1234"]}}}`,
		port, host, targetPort, private)
	if err := v.apply("h1", serverConfig(inbound)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	v.setUsers("in", 1, gate.User{ID: 1001, UUID: uuidA})

	out := fmt.Sprintf(`{"type":"vless","tag":"o-r","server":"127.0.0.1","server_port":%d,"uuid":"%s","flow":"xtls-rprx-vision",`+
		`"tls":{"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"%s","short_id":"abcd1234"}}}`,
		port, uuidA, public)
	c := newClient(t, map[string]string{"r": out})
	got, err := fetch(c.proxy("r"), v.target.URL, mib, 0)
	if err != nil || got != mib {
		t.Fatalf("reality: got=%d err=%v", got, err)
	}
	_, traffic, _, ok := v.g.Snapshot("in")
	if !ok {
		t.Fatal("no snapshot")
	}
	var sum int64
	for _, tr := range traffic {
		if tr.ID != 1001 {
			t.Fatalf("traffic of unexpected user %d", tr.ID)
		}
		sum += tr.Up + tr.Down
	}
	if sum < mib {
		t.Fatalf("counted %d bytes, want >= %d", sum, mib)
	}
}
