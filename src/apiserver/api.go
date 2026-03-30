package apiserver

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"sync"

	"github.com/rs/zerolog/log"
)

// TransportInfo holds live status of a single HEP transport connection.
type TransportInfo struct {
	Addr       string `json:"addr"`
	Proto      string `json:"proto"`
	Connected  bool   `json:"connected"`
	Reconnects int64  `json:"reconnects"`
}

// WebStats is the payload returned by GET /api/stats.
type WebStats struct {
	NodeName      string              `json:"node_name"`
	NodeID        int                 `json:"node_id"`
	UUID          string              `json:"uuid"`
	Interfaces    []string            `json:"interfaces"`
	CaptureModes  map[string][]string `json:"capture_modes"`
	UptimeSeconds int64               `json:"uptime_seconds"`
	Uptime        string              `json:"uptime"`
	Packets       struct {
		Total      int64 `json:"total"`
		SIP        int64 `json:"sip"`
		RTCP       int64 `json:"rtcp"`
		RTCPFail   int64 `json:"rtcp_fail"`
		RTP        int64 `json:"rtp"`
		DNS        int64 `json:"dns"`
		Log        int64 `json:"log"`
		HEPSent    int64 `json:"hep_sent"`
		Duplicates int64 `json:"duplicates"`
		Unknown    int64 `json:"unknown"`
	} `json:"packets"`
	Transport []TransportInfo `json:"transport"`
}

var (
	// transportsMu guards the transports map used for /api/stats.
	transportsMu sync.RWMutex
	transports   = map[string]*TransportInfo{}

	statsGetterMu sync.RWMutex
	statsGetter   func() WebStats
)

// RegisterStatsGetter registers a callback that provides live WebStats.
// It is called on every /api/stats request.
func RegisterStatsGetter(fn func() WebStats) {
	statsGetterMu.Lock()
	statsGetter = fn
	statsGetterMu.Unlock()
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	healthMu.RLock()
	payload := map[string]interface{}{
		"status":               "ok",
		"connected_transports": healthConnectedTotal,
		"queue_size":           healthQueueSize,
		"buffer_size_bytes":    healthBufferSize,
	}
	healthMu.RUnlock()

	if healthConnectedTotal == 0 {
		payload["status"] = "degraded"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func apiStatsHandler(w http.ResponseWriter, _ *http.Request) {
	statsGetterMu.RLock()
	fn := statsGetter
	statsGetterMu.RUnlock()

	var ws WebStats
	if fn != nil {
		ws = fn()
	}

	// Merge live transport info from the registry.
	transportsMu.RLock()
	ws.Transport = make([]TransportInfo, 0, len(transports))
	for _, t := range transports {
		ws.Transport = append(ws.Transport, *t)
	}
	transportsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws)
}

func makeWebUIHandler(uiFile string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if uiFile != "" {
			data, err := os.ReadFile(uiFile)
			if err == nil {
				_, _ = w.Write(data)
				return
			}
			log.Warn().Str("ui_file", uiFile).Err(err).Msg("Failed to read ui_file, falling back to embedded stats.html")
		}
		_, _ = w.Write([]byte(statsPage))
	}
}

// basicAuth wraps h with HTTP Basic Auth when username is non-empty.
// /health is always open. /metrics auth is controlled separately via prometheus_settings.auth.
func basicAuth(username, password string, h http.HandlerFunc) http.HandlerFunc {
	if username == "" {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="heplify stats"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// registerAPI mounts /health, /api/stats and / on mux.
func registerAPI(mux *http.ServeMux, user, pass, uiFile string) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/stats", basicAuth(user, pass, apiStatsHandler))
	mux.HandleFunc("/", basicAuth(user, pass, makeWebUIHandler(uiFile)))
}
