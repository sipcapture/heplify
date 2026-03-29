package sniffer

import (
	"testing"

	"github.com/sipcapture/heplify/src/config"
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
