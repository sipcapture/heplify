package promstats

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sipcapture/heplify/config"
)

var ConnectedClients = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "heplify_client_connects_in",
		Help: "No of inbound client connects",
	},
)

var ConnectionStatus = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "heplify_connection_status_out",
		Help: "Connection status OUT - 1 is connected, 0 is disconnected",
	},
)

var HepBytesInFile = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "heplify_hep_bytes_in_file",
		Help: "No of HEP bytes in file",
	},
)

var HepFileFlushesSuccess = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "heplify_hep_file_flushes_success",
		Help: "No of times HEP pakets from file have been successfully sent over network to backend HEP server",
	},
)

var HepFileFlushesError = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "heplify_hep_file_flushes_error",
		Help: "No of times HEP pakets from file failed sending over network to backend HEP server",
	},
)

var ClientLastMetricTimestamp = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "heplify_client_in_last_metric_timestamp",
		Help: "Inbound client's last metric arrival",
	},
)

func StartMetrics(wg *sync.WaitGroup) {
	wg.Add(1)
	prometheus.MustRegister(ConnectedClients)
	prometheus.MustRegister(ConnectionStatus)
	prometheus.MustRegister(HepBytesInFile)
	prometheus.MustRegister(HepFileFlushesSuccess)
	prometheus.MustRegister(HepFileFlushesError)
	prometheus.MustRegister(ClientLastMetricTimestamp)

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(config.Cfg.PrometheusIPPort, nil)
	wg.Done()

}
