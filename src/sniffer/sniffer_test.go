package sniffer

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/decoder"
)

func TestBuildBPFFilter(t *testing.T) {
	s := &Sniffer{cfg: &config.Config{}}
	filter := s.buildBPFFilter(config.SocketSettings{Vlan: true, Erspan: true})
	expected := "((udp or tcp) or proto 47) or (vlan and ((udp or tcp) or proto 47))"
	if filter != expected {
		t.Fatalf("unexpected filter: %s", filter)
	}
}

func TestBuildBPFFilterWithProtocols(t *testing.T) {
	s := &Sniffer{cfg: &config.Config{
		ProtocolSettings: []config.ProtocolSettings{
			{Name: "SIP", MinPort: 5060, MaxPort: 5090, Protocol: []string{"udp", "tcp"}},
		},
	}}
	filter := s.buildBPFFilter(config.SocketSettings{})
	expected := "(udp and portrange 5060-5090) or (tcp and portrange 5060-5090)"
	if filter != expected {
		t.Fatalf("unexpected filter: got %q, want %q", filter, expected)
	}
}

func TestMatchProtocolAndPort(t *testing.T) {
	setting := config.ProtocolSettings{
		Name:     "SIP",
		Protocol: []string{"udp", "tcp"},
		MinPort:  5060,
		MaxPort:  5090,
	}

	if !matchProtocol(setting, 0x11) { // udp
		t.Fatal("expected udp protocol match")
	}
	if matchProtocol(setting, 0x84) { // sctp
		t.Fatal("did not expect sctp protocol match")
	}
	if !matchPort(setting, 5060) || !matchPort(setting, 5090) {
		t.Fatal("expected port range boundary match")
	}
	if matchPort(setting, 6000) {
		t.Fatal("did not expect out-of-range port match")
	}
}

func TestStatsIncUpdatesPrometheusPacketCount(t *testing.T) {
	before := prometheusPacketCounterValue(t, "sip")
	stats := NewStats()

	stats.Inc(StatSIP)

	after := prometheusPacketCounterValue(t, "sip")
	if after != before+1 {
		t.Fatalf("packet counter after Inc(StatSIP) = %v, want %v", after, before+1)
	}
}

func prometheusPacketCounterValue(t *testing.T, packetType string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather prometheus metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "heplify_packet_count" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "type" && label.GetValue() == packetType {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestParseSIPMetricRequest(t *testing.T) {
	got, ok := parseSIPMetric([]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc\r\n\r\n"))
	if !ok {
		t.Fatal("expected SIP request metric")
	}
	if got.Method != "INVITE" || got.IsResponse || got.StatusCode != "" {
		t.Fatalf("unexpected request metric: %+v", got)
	}
}

func TestParseSIPMetricResponseWithCSeqMethod(t *testing.T) {
	got, ok := parseSIPMetric([]byte("SIP/2.0 200 OK\r\nCSeq: 42 REGISTER\r\n\r\n"))
	if !ok {
		t.Fatal("expected SIP response metric")
	}
	if !got.IsResponse || got.StatusCode != "200" || got.StatusClass != "2xx" || got.Method != "REGISTER" {
		t.Fatalf("unexpected response metric: %+v", got)
	}
}

func TestParseSIPMetricNormalizesUnknownMethods(t *testing.T) {
	req, ok := parseSIPMetric([]byte("X-RANDOM sip:bob@example.com SIP/2.0\r\n\r\n"))
	if !ok {
		t.Fatal("expected SIP-like request metric")
	}
	if req.Method != "UNKNOWN" {
		t.Fatalf("request method = %q, want UNKNOWN", req.Method)
	}

	resp, ok := parseSIPMetric([]byte("SIP/2.0 500 Server Error\r\nCSeq: 42 X-RANDOM\r\n\r\n"))
	if !ok {
		t.Fatal("expected SIP response metric")
	}
	if resp.Method != "UNKNOWN" {
		t.Fatalf("response CSeq method = %q, want UNKNOWN", resp.Method)
	}
}

func TestCarrierResolverMatchesSourceThenDestination(t *testing.T) {
	resolver := newCarrierResolver([]config.CarrierSettings{
		{Name: "alpha", CIDRs: []string{"10.0.0.0/24"}},
		{Name: "beta", CIDRs: []string{"192.0.2.0/24"}},
	})

	if got := resolver.Resolve(net.ParseIP("10.0.0.10"), net.ParseIP("192.0.2.20")); got != "alpha" {
		t.Fatalf("source carrier = %q, want alpha", got)
	}
	if got := resolver.Resolve(net.ParseIP("203.0.113.10"), net.ParseIP("192.0.2.20")); got != "beta" {
		t.Fatalf("destination fallback carrier = %q, want beta", got)
	}
	if got := resolver.Resolve(net.ParseIP("203.0.113.10"), net.ParseIP("198.51.100.20")); got != "other" {
		t.Fatalf("default carrier = %q, want other", got)
	}
}

func TestHandleSIPObservesRequestMetricWithCarrier(t *testing.T) {
	s := &Sniffer{
		cfg:   &config.Config{},
		stats: NewStats(),
		carriers: newCarrierResolver([]config.CarrierSettings{
			{Name: "alpha", CIDRs: []string{"10.0.0.0/24"}},
		}),
	}
	labels := map[string]string{"method": "INVITE", "carrier": "alpha"}
	before := prometheusCounterValue(t, "heplify_sip_requests_total", labels)

	s.handleSIP(testSIPPacket(
		net.ParseIP("10.0.0.10"),
		net.ParseIP("192.0.2.20"),
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: req-1\r\n\r\n"),
	), nil)

	after := prometheusCounterValue(t, "heplify_sip_requests_total", labels)
	if after != before+1 {
		t.Fatalf("SIP request counter = %v, want %v", after, before+1)
	}
}

func TestHandleSIPObservesResponseMetric(t *testing.T) {
	s := &Sniffer{cfg: &config.Config{}, stats: NewStats(), carriers: newCarrierResolver(nil)}
	labels := map[string]string{
		"status_code":  "486",
		"status_class": "4xx",
		"method":       "INVITE",
		"carrier":      "other",
	}
	before := prometheusCounterValue(t, "heplify_sip_responses_total", labels)

	s.handleSIP(testSIPPacket(
		net.ParseIP("192.0.2.20"),
		net.ParseIP("10.0.0.10"),
		[]byte("SIP/2.0 486 Busy Here\r\nCSeq: 42 INVITE\r\nCall-ID: resp-1\r\n\r\n"),
	), nil)

	after := prometheusCounterValue(t, "heplify_sip_responses_total", labels)
	if after != before+1 {
		t.Fatalf("SIP response counter = %v, want %v", after, before+1)
	}
}

func testSIPPacket(srcIP, dstIP net.IP, payload []byte) *decoder.Packet {
	return &decoder.Packet{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 5060,
		DstPort: 5060,
		Payload: payload,
	}
}

func prometheusCounterValue(t *testing.T, name string, labels map[string]string) float64 {
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
			if metricHasLabels(metric.GetLabel(), labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func metricHasLabels(metricLabels []*io_prometheus_client.LabelPair, want map[string]string) bool {
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
