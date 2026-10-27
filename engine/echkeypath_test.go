package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stls "github.com/sagernet/sing-box/common/tls"
)

// withECHKeyPath adds an ECH block that names a key file (the shape the panel
// sends when the operator filled the path instead of pasting the key).
func withECHKeyPath(inbound, path string) string {
	return strings.Replace(inbound, `"tls":{"enabled":true,`,
		`"tls":{"enabled":true,"ech":{"enabled":true,"key_path":"`+path+`"},`, 1)
}

// A key file this machine cannot read takes the whole document down, so the
// error names the inbound and the field instead of the inbound index alone.
func TestMissingECHKeyFileNamesTheInboundAndTheField(t *testing.T) {
	v := newEnv(t)
	const tag = "node12@machine3"
	cfg := serverConfig(withECHKeyPath(v.inbound("vless", tag, freePort(t)), "/nonexistent/ech.key"))

	err := v.e.Check([]byte(cfg))
	if err == nil {
		t.Fatal("Check accepted an ECH key path that does not exist")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want ErrInvalid", err)
	}
	for _, want := range []string{"inbounds[0]", `tag "` + tag + `"`, "tls.ech.key_path", "/nonexistent/ech.key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
	t.Logf("Check error: %v", err)

	if err := v.apply("bad", cfg); err == nil {
		t.Fatal("Apply accepted an ECH key path that does not exist")
	} else if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Apply err=%v, want ErrInvalid", err)
	}
}

// A file that reads but is not an ECH KEYS block is the core's own failure; it
// carries the inbound tag too.
func TestUnreadableECHKeyContentNamesTheInbound(t *testing.T) {
	v := newEnv(t)
	const tag = "node7@machine1"
	path := filepath.Join(v.dir, "not-a-key.pem")
	if err := os.WriteFile(path, []byte("not a pem at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := serverConfig(withECHKeyPath(v.inbound("vless", tag, freePort(t)), filepath.ToSlash(path)))

	err := v.e.Check([]byte(cfg))
	if err == nil {
		t.Fatal("Check accepted a file that is not an ECH KEYS block")
	}
	for _, want := range []string{"initialize inbound[0]", `tag "` + tag + `"`, "parse ECH keys"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
	t.Logf("Check error: %v", err)
}

// Every core inbound failure names its inbound, not only the ECH ones.
func TestACoreInboundErrorNamesTheInbound(t *testing.T) {
	v := newEnv(t)
	const tag = "node3@machine9"
	cfg := `{"inbounds":[{"type":"vless","tag":"` + tag + `","listen":"127.0.0.1","listen_port":1,"tls":{"enabled":true}}]}`

	err := v.e.Check([]byte(cfg))
	if err == nil {
		t.Fatal("Check accepted an inbound without a certificate")
	}
	for _, want := range []string{"initialize inbound[0]", "missing certificate", `tag "` + tag + `"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
	t.Logf("Check error: %v", err)
}

// An inline key wins over the path, so the path is not read and cannot refuse
// the document: only the core's own parse of the inline key can.
func TestAnInlineECHKeyLeavesThePathUnused(t *testing.T) {
	v := newEnv(t)
	inbound := strings.Replace(v.inbound("vless", "in", freePort(t)), `"tls":{"enabled":true,`,
		`"tls":{"enabled":true,"ech":{"enabled":true,"key":["not-a-key"],"key_path":"/nonexistent/ech.key"},`, 1)

	err := v.e.Check([]byte(serverConfig(inbound)))
	if err == nil {
		t.Fatal("Check accepted a garbage inline ECH key")
	}
	if strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("the unused key_path was read: %v", err)
	}
	t.Logf("Check error: %v", err)
}

// The pre-flight is a readability check only: a key file that reads must not be
// refused by it.
func TestAnECHKeyFileThatReadsPassesThePreFlight(t *testing.T) {
	v := newEnv(t)
	_, keyPEM, err := stls.ECHKeygenDefault("public.example.com")
	if err != nil {
		t.Fatalf("ECHKeygenDefault: %v", err)
	}
	path := filepath.Join(v.dir, "ech-key.pem")
	if err := os.WriteFile(path, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := serverConfig(withECHKeyPath(v.inbound("vless", "in", freePort(t)), filepath.ToSlash(path)))
	if err := v.e.Check([]byte(cfg)); err != nil {
		t.Fatalf("Check refused a readable ECH key file: %v", err)
	}
}
