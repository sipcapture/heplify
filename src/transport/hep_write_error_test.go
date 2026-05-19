package transport

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/hep"
)

func TestIsMessageTooLong(t *testing.T) {
	if !isMessageTooLong(syscall.EMSGSIZE) {
		t.Fatal("expected EMSGSIZE")
	}
	if !isMessageTooLong(errors.New("write udp 1.2.3.4:1->5.6.7.8:9060: write: message too long")) {
		t.Fatal("expected string match")
	}
	if isMessageTooLong(errors.New("connection refused")) {
		t.Fatal("unexpected match")
	}
}

func TestEnrichMessageTooLongLog_noPanic(t *testing.T) {
	msg := &hep.Msg{
		Version:   0x02,
		Protocol:  0x11,
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   5060,
		DstPort:   5060,
		ProtoType: 1,
		Payload:   []byte("INVITE sip:x SIP/2.0\r\n"),
	}
	pkt := hep.Encode(msg)
	ev := log.Error()
	_ = enrichMessageTooLongLog(ev, pkt, len(pkt), true)
	if len(hep.PayloadBytes(pkt)) == 0 {
		t.Fatal("expected payload bytes")
	}
}
