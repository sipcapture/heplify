package apiserver

import (
	"net"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/prometheus/client_golang/prometheus"
)

// RTCP JSON paths — same as heplify-server metric/definition.go rtcpPaths.
var rtcpPaths = [][]string{
	{"report_blocks", "[0]", "fraction_lost"},
	{"report_blocks", "[0]", "packets_lost"},
	{"report_blocks", "[0]", "ia_jitter"},
	{"report_blocks", "[0]", "dlsr"},
	{"report_blocks_xr", "fraction_lost"},
	{"report_blocks_xr", "fraction_discard"},
	{"report_blocks_xr", "burst_density"},
	{"report_blocks_xr", "gap_density"},
	{"report_blocks_xr", "burst_duration"},
	{"report_blocks_xr", "gap_duration"},
	{"report_blocks_xr", "round_trip_delay"},
	{"report_blocks_xr", "end_system_delay"},
}

var (
	rtcpFractionLost = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcp_fraction_lost", Help: "RTCP fraction lost"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpPacketsLost = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcp_packets_lost", Help: "RTCP packets lost"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpJitter = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcp_jitter", Help: "RTCP jitter"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpDLSR = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcp_dlsr", Help: "RTCP dlsr"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrFractionLost = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_fraction_lost", Help: "RTCPXR fraction lost"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrFractionDiscard = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_fraction_discard", Help: "RTCPXR fraction discard"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrBurstDensity = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_burst_density", Help: "RTCPXR burst density"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrBurstDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_burst_duration", Help: "RTCPXR burst duration"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrGapDensity = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_gap_density", Help: "RTCPXR gap density"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrGapDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_gap_duration", Help: "RTCPXR gap duration"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrRoundTripDelay = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_round_trip_delay", Help: "RTCPXR round trip delay"},
		[]string{"target_name", "direction", "node_id"},
	)
	rtcpxrEndSystemDelay = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "heplify_rtcpxr_end_system_delay", Help: "RTCPXR end system delay"},
		[]string{"target_name", "direction", "node_id"},
	)
)

func init() {
	prometheus.MustRegister(rtcpFractionLost)
	prometheus.MustRegister(rtcpPacketsLost)
	prometheus.MustRegister(rtcpJitter)
	prometheus.MustRegister(rtcpDLSR)
	prometheus.MustRegister(rtcpxrFractionLost)
	prometheus.MustRegister(rtcpxrFractionDiscard)
	prometheus.MustRegister(rtcpxrBurstDensity)
	prometheus.MustRegister(rtcpxrBurstDuration)
	prometheus.MustRegister(rtcpxrGapDensity)
	prometheus.MustRegister(rtcpxrGapDuration)
	prometheus.MustRegister(rtcpxrRoundTripDelay)
	prometheus.MustRegister(rtcpxrEndSystemDelay)
}

func normMax(val float64) float64 {
	if val > 10000000 {
		return 0
	}
	return val
}

// BuildPromTargetMap parses comma-separated PromTargetIP and PromTargetName like heplify-server.
// Returns nil when labeling should fall back to ("unknown", "") only.
func BuildPromTargetMap(ipCSV, nameCSV string) map[string]string {
	ipCSV = strings.TrimSpace(ipCSV)
	nameCSV = strings.TrimSpace(nameCSV)
	if ipCSV == "" || nameCSV == "" {
		return nil
	}
	ips := splitCommaTrim(ipCSV)
	names := splitCommaTrim(nameCSV)
	if len(ips) != len(names) || len(ips) == 0 {
		return nil
	}
	if ips[0] == "" || names[0] == "" {
		return nil
	}
	m := make(map[string]string, len(ips))
	for i := range ips {
		ip := net.ParseIP(ips[i])
		if ip == nil {
			continue
		}
		m[ip.String()] = names[i]
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func splitCommaTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// ObserveRTCPMetrics updates RTCP / RTCP-XR gauges from HEP-style JSON (same payload as heplify-server ProtoType 5).
// promTargetMap: from BuildPromTargetMap; nil means a single update with target_name=unknown, direction="".
func ObserveRTCPMetrics(payload []byte, nodeName string, srcIP, dstIP net.IP, promTargetMap map[string]string) {
	if len(payload) == 0 {
		return
	}
	if nodeName == "" {
		nodeName = "unknown"
	}

	if promTargetMap == nil {
		dissectRTCPStats("unknown", "", nodeName, payload)
		return
	}

	srcKey := ""
	if srcIP != nil {
		srcKey = srcIP.String()
	}
	dstKey := ""
	if dstIP != nil {
		dstKey = dstIP.String()
	}

	srcTarget, srcHit := promTargetMap[srcKey]
	dstTarget, dstHit := promTargetMap[dstKey]

	if srcHit {
		dissectRTCPStats(srcTarget, "src", nodeName, payload)
	}
	if dstHit {
		dissectRTCPStats(dstTarget, "dst", nodeName, payload)
	}
	if !srcHit && !dstHit {
		dissectRTCPStats("unknown", "", nodeName, payload)
	}
}

func dissectRTCPStats(targetName string, direction string, nodeID string, data []byte) {
	jsonparser.EachKey(data, func(idx int, value []byte, vt jsonparser.ValueType, err error) {
		switch idx {
		case 0:
			if fractionLost, err := jsonparser.ParseFloat(value); err == nil {
				rtcpFractionLost.WithLabelValues(targetName, direction, nodeID).Set(normMax(fractionLost))
			}
		case 1:
			if packetsLost, err := jsonparser.ParseFloat(value); err == nil {
				rtcpPacketsLost.WithLabelValues(targetName, direction, nodeID).Set(normMax(packetsLost))
			}
		case 2:
			if iaJitter, err := jsonparser.ParseFloat(value); err == nil {
				rtcpJitter.WithLabelValues(targetName, direction, nodeID).Set(normMax(iaJitter))
			}
		case 3:
			if dlsr, err := jsonparser.ParseFloat(value); err == nil {
				rtcpDLSR.WithLabelValues(targetName, direction, nodeID).Set(normMax(dlsr))
			}
		case 4:
			if fractionLost, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrFractionLost.WithLabelValues(targetName, direction, nodeID).Set(fractionLost)
			}
		case 5:
			if fractionDiscard, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrFractionDiscard.WithLabelValues(targetName, direction, nodeID).Set(fractionDiscard)
			}
		case 6:
			if burstDensity, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrBurstDensity.WithLabelValues(targetName, direction, nodeID).Set(burstDensity)
			}
		case 7:
			if gapDensity, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrGapDensity.WithLabelValues(targetName, direction, nodeID).Set(gapDensity)
			}
		case 8:
			if burstDuration, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrBurstDuration.WithLabelValues(targetName, direction, nodeID).Set(burstDuration)
			}
		case 9:
			if gapDuration, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrGapDuration.WithLabelValues(targetName, direction, nodeID).Set(gapDuration)
			}
		case 10:
			if roundTripDelay, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrRoundTripDelay.WithLabelValues(targetName, direction, nodeID).Set(roundTripDelay)
			}
		case 11:
			if endSystemDelay, err := jsonparser.ParseFloat(value); err == nil {
				rtcpxrEndSystemDelay.WithLabelValues(targetName, direction, nodeID).Set(endSystemDelay)
			}
		}
	}, rtcpPaths...)
}
