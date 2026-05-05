package apiserver

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// Same fixture as heplify-server/metric/prometheus_test.go RTCPStat.
const rtcpStatJSON = `{"sender_information":{"ntp_timestamp_sec":3719322562,"ntp_timestamp_usec":3758534470,"rtp_timestamp":360902880,"packets":4017,"octets":642720},"ssrc":2543003035,"type":202,"report_count":1,"report_blocks":[{"source_ssrc":1393754395,"fraction_lost":0,"packets_lost":0,"highest_seq_no":29662,"ia_jitter":159,"lsr":0,"dlsr":0}],"report_blocks_xr":{"end_system_delay":11},"sdes_ssrc":2540000035}`

func TestObserveRTCPMetricsUnknownTarget(t *testing.T) {
	node := "test-node"
	ObserveRTCPMetrics([]byte(rtcpStatJSON), node, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), nil)

	labels := map[string]string{"target_name": "unknown", "direction": "", "node_id": node}
	if v := prometheusGaugeValue(t, "heplify_rtcp_jitter", labels); v != 159 {
		t.Fatalf("heplify_rtcp_jitter = %v, want 159", v)
	}
	if v := prometheusGaugeValue(t, "heplify_rtcp_fraction_lost", labels); v != 0 {
		t.Fatalf("heplify_rtcp_fraction_lost = %v, want 0", v)
	}
	if v := prometheusGaugeValue(t, "heplify_rtcpxr_end_system_delay", labels); v != 11 {
		t.Fatalf("heplify_rtcpxr_end_system_delay = %v, want 11", v)
	}
}

func TestObserveRTCPMetricsPromTargetsSrcDst(t *testing.T) {
	m := BuildPromTargetMap("192.168.245.250,192.168.247.250", "proxy_inc_ip,proxy_out_ip")
	if m == nil {
		t.Fatal("BuildPromTargetMap: expected non-nil map")
	}
	node := "edge"
	src := net.ParseIP("192.168.245.250")
	dst := net.ParseIP("192.168.247.250")
	ObserveRTCPMetrics([]byte(rtcpStatJSON), node, src, dst, m)

	srcLabels := map[string]string{"target_name": "proxy_inc_ip", "direction": "src", "node_id": node}
	if v := prometheusGaugeValue(t, "heplify_rtcp_jitter", srcLabels); v != 159 {
		t.Fatalf("src jitter = %v, want 159", v)
	}
	dstLabels := map[string]string{"target_name": "proxy_out_ip", "direction": "dst", "node_id": node}
	if v := prometheusGaugeValue(t, "heplify_rtcp_jitter", dstLabels); v != 159 {
		t.Fatalf("dst jitter = %v, want 159", v)
	}
}

func TestObserveRTCPMetricsNoTargetHit(t *testing.T) {
	m := BuildPromTargetMap("192.168.245.250", "proxy_inc_ip")
	node := "n1"
	ObserveRTCPMetrics([]byte(rtcpStatJSON), node, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), m)
	labels := map[string]string{"target_name": "unknown", "direction": "", "node_id": node}
	if v := prometheusGaugeValue(t, "heplify_rtcp_jitter", labels); v != 159 {
		t.Fatalf("unknown jitter = %v, want 159", v)
	}
}

func TestBuildPromTargetMapInvalid(t *testing.T) {
	if BuildPromTargetMap("", "") != nil {
		t.Fatal("expected nil")
	}
	if BuildPromTargetMap("10.0.0.1", "a,b") != nil {
		t.Fatal("unbalanced lists should return nil")
	}
}

func prometheusGaugeValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather prometheus metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabelsGauge(metric.GetLabel(), labels) {
				return metric.GetGauge().GetValue()
			}
		}
	}
	return 0
}

func metricHasLabelsGauge(metricLabels []*io_prometheus_client.LabelPair, want map[string]string) bool {
	for name, value := range want {
		found := false
		for _, label := range metricLabels {
			if label.GetName() == name && label.GetValue() == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
