package apiserver

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"
)

// TransportInfo holds live status of a single HEP transport connection.
type TransportInfo struct {
	Addr       string `json:"addr"`
	Proto      string `json:"proto"`
	Connected  bool   `json:"connected"`
	Reconnects int64  `json:"reconnects"`
	Sent       int64  `json:"sent"`
	Errors     int64  `json:"errors"`
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
		Diameter   int64 `json:"diameter"`
		Log        int64 `json:"log"`
		HEPSent    int64 `json:"hep_sent"`
		Duplicates int64 `json:"duplicates"`
		Unknown    int64 `json:"unknown"`
	} `json:"packets"`
	Transport []TransportInfo `json:"transport"`
}

var (
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
	connected := healthConnectedTotal
	payload := map[string]interface{}{
		"status":               "ok",
		"connected_transports": connected,
		"queue_size":           healthQueueSize,
		"buffer_size_bytes":    healthBufferSize,
	}
	healthMu.RUnlock()

	if connected == 0 {
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

	transportsMu.RLock()
	ws.Transport = make([]TransportInfo, 0, len(transports))
	for _, t := range transports {
		ws.Transport = append(ws.Transport, *t)
	}
	transportsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws)
}

// basicAuth wraps h with HTTP Basic Auth when username is non-empty.
// /health is always open. /metrics auth is controlled separately via prometheus_settings.auth.
func basicAuth(username, password string, h http.HandlerFunc) http.HandlerFunc {
	if username == "" {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Compare fixed-size hashes so the response time does not reveal the
		// credential lengths; evaluate both to avoid an early exit.
		userOK := secretEqual(u, username)
		passOK := secretEqual(p, password)
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="heplify stats"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// secretEqual compares two secrets in time that depends only on their
// lengths, not on where they differ. Unlike subtle.ConstantTimeCompare it
// does not return early when the lengths differ.
func secretEqual(got, want string) bool {
	n := len(got)
	if len(want) > n {
		n = len(want)
	}
	var diff byte
	for i := 0; i < n; i++ {
		var a, b byte
		if i < len(got) {
			a = got[i]
		}
		if i < len(want) {
			b = want[i]
		}
		diff |= a ^ b
	}
	return subtle.ConstantTimeEq(int32(len(got)), int32(len(want)))&subtle.ConstantTimeByteEq(diff, 0) == 1
}

// registerAPI mounts /health and /api/stats on mux.
func registerAPI(mux *http.ServeMux, user, pass string) {
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/stats", basicAuth(user, pass, apiStatsHandler))
}
