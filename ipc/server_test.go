package ipc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray-prism/engine"
	"github.com/W1nCwC/W1nCray-prism/gate"
)

type fixture struct {
	t    *testing.T
	srv  *httptest.Server
	eng  *engine.Engine
	cert string
	key  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)

	g := gate.New()
	e, err := engine.New(filepath.Join(dir, "state"), g)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(e, g))
	t.Cleanup(func() { srv.Close(); _ = e.Close() })

	return &fixture{t: t, srv: srv, eng: e, cert: strings.ReplaceAll(cp, `\`, `/`), key: strings.ReplaceAll(kp, `\`, `/`)}
}

func (f *fixture) call(method, path string, body any, headers ...string) (int, map[string]any) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	req.Header.Set("X-Prism-Api", "1")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)

	return resp.StatusCode, out
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

func (f *fixture) config(port int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"anytls","tag":"in","listen":"127.0.0.1","listen_port":%d,"tls":{"enabled":true,"certificate_path":"%s","key_path":"%s"}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, port, f.cert, f.key))
}

func TestTheApiHeaderIsRequired(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/status", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	req.Header.Set("X-Prism-Api", "2")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("a different api version was accepted: %d", resp.StatusCode)
	}
}

func TestConfigUsersStatsLifecycle(t *testing.T) {
	f := newFixture(t)
	code, st := f.call("GET", "/v1/status", nil)
	if code != 200 || st["state"] != "idle" || st["api"] != float64(1) || st["boot_id"] == "" {
		t.Fatalf("initial status: %d %v", code, st)
	}
	boot := st["boot_id"].(string)

	port := freePort(t)
	code, out := f.call("PUT", "/v1/config", map[string]any{"hash": "h1", "config": f.config(port)})
	if code != 200 || out["applied"] != "h1" || out["noop"] != false {
		t.Fatalf("put config: %d %v", code, out)
	}
	code, out = f.call("PUT", "/v1/config", map[string]any{"hash": "h1", "config": f.config(port)})
	if code != 200 || out["noop"] != true {
		t.Fatalf("same hash: %d %v", code, out)
	}

	// A broken config is a 422 that names the kept hash.
	code, out = f.call("PUT", "/v1/config", map[string]any{"hash": "h2", "config": json.RawMessage(`{"inbounds":[{"type":"mixed","tag":"x","listen":"127.0.0.1","listen_port":1}]}`)})
	if code != 422 || out["error"] != "invalid" || out["kept"] != "h1" {
		t.Fatalf("invalid config: %d %v", code, out)
	}
	code, out = f.call("PUT", "/v1/config", map[string]any{"hash": "", "config": json.RawMessage(`{}`)})
	if code != 422 {
		t.Fatalf("empty hash: %d %v", code, out)
	}

	code, out = f.call("POST", "/v1/check", map[string]any{"config": f.config(freePort(t))})
	if code != 200 || out["ok"] != true {
		t.Fatalf("check: %d %v", code, out)
	}
	code, _ = f.call("POST", "/v1/check", map[string]any{"config": json.RawMessage(`{"nonsense":1}`)})
	if code != 422 {
		t.Fatalf("check of a bad config: %d", code)
	}

	code, out = f.call("PUT", "/v1/users/nope", map[string]any{"seq": 1, "users": []gate.User{{ID: 1, UUID: "u"}}})
	if code != 404 {
		t.Fatalf("users for an unknown tag: %d %v", code, out)
	}
	code, out = f.call("PUT", "/v1/users/in", map[string]any{"seq": 1, "users": []gate.User{{ID: 1, UUID: "u-1"}, {ID: 2, UUID: "u-2"}}})
	if code != 200 || out["added"] != float64(2) || out["applied"] != true {
		t.Fatalf("users: %d %v", code, out)
	}
	code, out = f.call("PUT", "/v1/users/in", map[string]any{"seq": 1, "users": []gate.User{{ID: 3, UUID: "u-3"}}})
	if code != 200 || out["added"] != float64(1) {
		t.Fatalf("a repeated seq must still apply: %d %v", code, out)
	}
	code, out = f.call("PUT", "/v1/users/in", map[string]any{"seq": 0, "users": []gate.User{{ID: 0, UUID: "u"}}})
	if code != 422 {
		t.Fatalf("a user id of 0: %d %v", code, out)
	}

	code, _ = f.call("PUT", "/v1/devices/in", map[string]any{"alive": map[string]int{"3": 2}})
	if code != 200 {
		t.Fatalf("devices: %d", code)
	}

	code, out = f.call("GET", "/v1/stats?tag=in", nil)
	if code != 200 || out["boot_id"] != boot || out["snapshot"] == nil {
		t.Fatalf("stats: %d %v", code, out)
	}
	snap := out["snapshot"]
	code, _ = f.call("POST", "/v1/stats/commit", map[string]any{"tag": "in", "snapshot": snap, "boot_id": "other"})
	if code != 409 {
		t.Fatalf("commit with a foreign boot id: %d", code)
	}
	code, _ = f.call("POST", "/v1/stats/commit", map[string]any{"tag": "in", "snapshot": snap, "boot_id": boot})
	if code != 200 {
		t.Fatalf("commit: %d", code)
	}
	code, _ = f.call("POST", "/v1/stats/commit", map[string]any{"tag": "in", "snapshot": snap, "boot_id": boot})
	if code != 409 {
		t.Fatalf("a second commit: %d", code)
	}
	code, _ = f.call("GET", "/v1/stats?tag=nope", nil)
	if code != 404 {
		t.Fatalf("stats of an unknown tag: %d", code)
	}

	code, st = f.call("GET", "/v1/status", nil)
	if st["state"] != "running" || st["config_hash"] != "h1" || st["rejected_hash"] != "h2" {
		t.Fatalf("status: %d %v", code, st)
	}
}
