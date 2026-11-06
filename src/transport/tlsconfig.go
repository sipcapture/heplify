package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	"github.com/sipcapture/heplify/src/config"
)

// buildTLSConfig returns the client TLS settings for one transport: TLS 1.2
// minimum, an optional private CA, an optional client certificate (mTLS) and
// an optional server name override.
func buildTLSConfig(t config.TransportSettings) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.SkipVerify, //nolint:gosec // opt-in, warned about at dial time
		ServerName:         t.ServerName,
	}
	if cfg.ServerName == "" && net.ParseIP(t.Host) == nil {
		cfg.ServerName = t.Host
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificates", t.CAFile)
		}
		cfg.RootCAs = pool
	}
	if t.CertFile != "" || t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
