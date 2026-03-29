package promstats

import (
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

var (
	healthMu             sync.RWMutex
	healthQueueSize      int
	healthConnectedTotal int
	healthBufferSize     int64
)

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
	refreshConnectedTotal()
}

func IncReconnect(addr, proto string) {
	HepReconnectCount.WithLabelValues(addr, proto).Inc()
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

func StartMetrics(cfg *config.Config) {
	if !cfg.PrometheusSettings.Active {
		return
	}

	addr := fmt.Sprintf("%s:%d", cfg.PrometheusSettings.Host, cfg.PrometheusSettings.Port)
	if cfg.PrometheusSettings.Port == 0 {
		addr = ":9096"
	}

	log.Info().Str("addr", addr).Msg("Starting Prometheus Metrics Server")

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("Failed to start Prometheus Metrics Server")
		}
	}()
}
