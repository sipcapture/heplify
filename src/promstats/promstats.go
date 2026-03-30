package promstats

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
)

var (
	PacketCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "heplify_packet_count",
			Help: "Total number of packets captured",
		},
		[]string{"type"},
	)
	HepSentCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "heplify_hep_sent_count",
			Help: "Total number of HEP packets sent",
		},
	)
	HepErrorCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "heplify_hep_error_count",
			Help: "Total number of HEP send errors",
		},
	)
	HepDroppedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "heplify_hep_dropped_count",
			Help: "Total number of dropped HEP packets",
		},
	)
	HepReconnectCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "heplify_hep_reconnect_count",
			Help: "Total number of reconnect attempts per transport",
		},
		[]string{"addr", "proto"},
	)
	HepQueueSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "heplify_hep_queue_size",
			Help: "Current depth of HEP send queue",
		},
	)
	HepBufferSizeBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "heplify_hep_buffer_size_bytes",
			Help: "Current size of on-disk HEP buffer file",
		},
	)
	HepTransportConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "heplify_hep_transport_connected",
			Help: "Transport connection status (1 connected, 0 disconnected)",
		},
		[]string{"addr", "proto"},
	)
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
	healthMu             sync.RWMutex
	healthQueueSize      int
	healthConnectedTotal int
	healthBufferSize     int64

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

func init() {
	prometheus.MustRegister(PacketCount)
	prometheus.MustRegister(HepSentCount)
	prometheus.MustRegister(HepErrorCount)
	prometheus.MustRegister(HepDroppedCount)
	prometheus.MustRegister(HepReconnectCount)
	prometheus.MustRegister(HepQueueSize)
	prometheus.MustRegister(HepBufferSizeBytes)
	prometheus.MustRegister(HepTransportConnected)
}

func SetQueueSize(v int) {
	HepQueueSize.Set(float64(v))
	healthMu.Lock()
	healthQueueSize = v
	healthMu.Unlock()
}

func SetBufferSizeBytes(v int64) {
	HepBufferSizeBytes.Set(float64(v))
	healthMu.Lock()
	healthBufferSize = v
	healthMu.Unlock()
}

func SetTransportConnected(addr, proto string, connected bool) {
	value := 0.0
	if connected {
		value = 1
	}
	HepTransportConnected.WithLabelValues(addr, proto).Set(value)

	key := proto + "://" + addr
	transportsMu.Lock()
	if t, ok := transports[key]; ok {
		t.Connected = connected
	} else {
		transports[key] = &TransportInfo{Addr: addr, Proto: proto, Connected: connected}
	}
	transportsMu.Unlock()

	refreshConnectedTotal()
}

func IncReconnect(addr, proto string) {
	HepReconnectCount.WithLabelValues(addr, proto).Inc()

	key := proto + "://" + addr
	transportsMu.Lock()
	if t, ok := transports[key]; ok {
		t.Reconnects++
	} else {
		transports[key] = &TransportInfo{Addr: addr, Proto: proto, Reconnects: 1}
	}
	transportsMu.Unlock()
}

func refreshConnectedTotal() {
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return
	}
	total := 0
	for _, mf := range metricFamilies {
		if mf.GetName() != "heplify_hep_transport_connected" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if int(m.GetGauge().GetValue()) == 1 {
				total++
			}
		}
	}
	healthMu.Lock()
	healthConnectedTotal = total
	healthMu.Unlock()
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

func webUIHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(statsPage))
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

	if cfg.PrometheusSettings.Active && cfg.PrometheusSettings.Auth && user == "" {
		log.Warn().Msg("prometheus_settings.auth is true but api_settings.username is empty — /metrics will NOT be protected")
	}

	mux := http.NewServeMux()
	if cfg.PrometheusSettings.Active {
		metricsHandler := promhttp.Handler()
		if cfg.PrometheusSettings.Auth {
			mux.Handle("/metrics", basicAuth(user, pass, metricsHandler.ServeHTTP))
		} else {
			mux.Handle("/metrics", metricsHandler)
		}
		log.Info().Str("addr", addr).Bool("auth", cfg.PrometheusSettings.Auth).Msg("Prometheus /metrics endpoint enabled")
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/stats", basicAuth(user, pass, apiStatsHandler))
	mux.HandleFunc("/", basicAuth(user, pass, webUIHandler))
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("Failed to start API Server")
		}
	}()
}
