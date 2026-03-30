package promstats

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
)

// StartMetrics creates the shared HTTP mux, registers Prometheus and API
// routes on it, and starts the server in a goroutine.
func StartMetrics(cfg *config.Config) {
	if !cfg.ApiSettings.Active {
		return
	}

	addr := fmt.Sprintf("%s:%d", cfg.ApiSettings.Host, cfg.ApiSettings.Port)
	if cfg.ApiSettings.Port == 0 {
		addr = ":9096"
	}

	log.Info().Str("addr", addr).Msg("Starting API / Web Stats Server")

	user := cfg.ApiSettings.Username
	pass := cfg.ApiSettings.Password
	if user != "" {
		log.Info().Str("addr", addr).Msg("Web stats UI protected by HTTP Basic Auth")
	}

	mux := http.NewServeMux()

	registerPrometheus(mux, cfg, user, pass)
	registerAPI(mux, user, pass, cfg.ApiSettings.UIFile)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("Failed to start API Server")
		}
	}()
}
