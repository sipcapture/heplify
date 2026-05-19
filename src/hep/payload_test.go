package hep

import (
	"net"
	"testing"
)

func TestPayloadBytes(t *testing.T) {
	msg := &Msg{
		Version:   0x02,
		Protocol:  0x11,
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   5060,
		DstPort:   5060,
		Tsec:      1,
		Tmsec:     2,
		ProtoType: 1,
		NodeID:    1,
		Payload:   []byte("INVITE sip:test SIP/2.0\r\n"),
	}
	pkt := Encode(msg)
	got := PayloadBytes(pkt)
	if string(got) != string(msg.Payload) {
		t.Fatalf("payload: got %q want %q", got, msg.Payload)
	}
}

func TestPayloadBytes_invalid(t *testing.T) {
	if PayloadBytes([]byte("HEP2")) != nil {
		t.Fatal("expected nil for invalid packet")
	}
}
