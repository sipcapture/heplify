package apiserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
)

// StartMetrics starts both the API web server and the Prometheus metrics server
// if they are configured. Both run independently on their own addresses.
func StartMetrics(cfg *config.Config) {
	StartAPIServer(cfg)
	StartPrometheusServer(cfg)
}

// StartAPIServer starts the web stats UI and REST API (/, /api/stats, /health).
func StartAPIServer(cfg *config.Config) {
	if !cfg.ApiSettings.Active {
		return
	}

	addr := fmt.Sprintf("%s:%d", cfg.ApiSettings.Host, cfg.ApiSettings.Port)
	if cfg.ApiSettings.Port == 0 {
		addr = ":9060"
	}

	user := cfg.ApiSettings.Username
	pass := cfg.ApiSettings.Password

	if user != "" {
		log.Info().Str("addr", addr).Msg("API server protected by HTTP Basic Auth")
	}

	mux := http.NewServeMux()
	registerAPI(mux, user, pass)

	srv := newHTTPServer(addr, mux)
	if cfg.ApiSettings.TLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Info().Str("addr", addr).Str("cert", cfg.ApiSettings.CertFile).Msg("Starting API server (HTTPS)")
		go func() {
			if err := srv.ListenAndServeTLS(cfg.ApiSettings.CertFile, cfg.ApiSettings.KeyFile); err != nil {
				log.Error().Err(err).Msg("API server (HTTPS) failed")
			}
		}()
		return
	}

	if user != "" {
		log.Warn().Str("addr", addr).Msg("API Basic Auth over plain HTTP sends the password in clear text; enable api_settings.tls")
	}
	log.Info().Str("addr", addr).Msg("Starting API server (HTTP)")
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("API server failed")
		}
	}()
}

// StartPrometheusServer starts the Prometheus /metrics endpoint on its own address.
func StartPrometheusServer(cfg *config.Config) {
	if !cfg.PrometheusSettings.Active {
		return
	}

	if cfg.PrometheusSettings.Auth && cfg.ApiSettings.Username == "" {
		log.Warn().Msg("prometheus_settings.auth is true but api_settings.username is empty — metrics will be unprotected")
	}

	addr := fmt.Sprintf("%s:%d", cfg.PrometheusSettings.Host, cfg.PrometheusSettings.Port)

	log.Info().Str("addr", addr).Msg("Starting Prometheus metrics server")

	mux := http.NewServeMux()
	registerPrometheus(mux, cfg, cfg.ApiSettings.Username, cfg.ApiSettings.Password)

	srv := newHTTPServer(addr, mux)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("Prometheus server failed")
		}
	}()
}

// newHTTPServer returns a server with timeouts, so slow or idle clients
// (slowloris) cannot hold connections and goroutines open forever.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
