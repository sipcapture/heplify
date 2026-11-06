package transport

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sipcapture/heplify/src/config"
)

func TestBuildTLSConfigCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// Without the CA the self-signed server is rejected.
	noCA, err := buildTLSConfig(config.TransportSettings{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := tls.Dial("tcp", net.JoinHostPort(host, port), noCA); err == nil {
		c.Close()
		t.Fatal("self-signed server accepted without ca_file")
	}

	withCA, err := buildTLSConfig(config.TransportSettings{Host: host, CAFile: caPath, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if withCA.MinVersion != tls.VersionTLS12 {
		t.Fatal("MinVersion not TLS 1.2")
	}
	c, err := tls.Dial("tcp", net.JoinHostPort(host, port), withCA)
	if err != nil {
		t.Fatalf("dial with ca_file: %v", err)
	}
	c.Close()
}

func TestBuildTLSConfigErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if _, err := buildTLSConfig(config.TransportSettings{CAFile: bad}); err == nil {
		t.Fatal("garbage ca_file accepted")
	}
	if _, err := buildTLSConfig(config.TransportSettings{CertFile: bad, KeyFile: bad}); err == nil {
		t.Fatal("garbage client certificate accepted")
	}
}
