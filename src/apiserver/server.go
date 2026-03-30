package apiserver

import (
	"fmt"
	"net/http"

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

	if cfg.ApiSettings.TLS {
		log.Info().Str("addr", addr).Str("cert", cfg.ApiSettings.CertFile).Msg("Starting API server (HTTPS)")
		go func() {
			if err := http.ListenAndServeTLS(addr, cfg.ApiSettings.CertFile, cfg.ApiSettings.KeyFile, mux); err != nil {
				log.Error().Err(err).Msg("API server (HTTPS) failed")
			}
		}()
		return
	}

	log.Info().Str("addr", addr).Msg("Starting API server (HTTP)")
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
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

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("Prometheus server failed")
		}
	}()
}
