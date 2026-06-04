package decoder

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func TestHepTimestampFromCapture_sequence(t *testing.T) {
	ts := time.Unix(1_700_000_000, 818142*1000)
	tsec, tmsec := hepTimestampFromCapture(ts, 0)
	if tsec != uint32(ts.Unix()) || tmsec != 818142 {
		t.Fatalf("seq 0: got tsec=%d tmsec=%d", tsec, tmsec)
	}
	tsec, tmsec = hepTimestampFromCapture(ts, 1)
	if tsec != uint32(ts.Unix()) || tmsec != 818143 {
		t.Fatalf("seq 1: got tsec=%d tmsec=%d want tsec=%d tmsec=818143", tsec, tmsec, uint32(ts.Unix()))
	}
}

func TestHepTimestampFromCapture_overflowSecond(t *testing.T) {
	ts := time.Unix(100, 999_999*1000)
	tsec, tmsec := hepTimestampFromCapture(ts, 1)
	if tsec != 101 || tmsec != 0 {
		t.Fatalf("overflow: got tsec=%d tmsec=%d want 101/0", tsec, tmsec)
	}
}

func TestTCPSIPDistinctTmsecPerMessage(t *testing.T) {
	msg1 := []byte("INVITE sip:a@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	msg2 := []byte("ACK sip:a@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	combined := append(append([]byte{}, msg1...), msg2...)

	var received []*Packet
	cb := func(pkt *Packet) { received = append(received, pkt) }

	s := &sipStream{
		net:       gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}),
		transport: gopacket.NewFlow(0, []byte{0x13, 0xc4}, []byte{0x13, 0xc4}),
		cb:        cb,
		buf:       make([]byte, 0, 4096),
	}

	ts := time.Unix(1_778_592_875, 818142*1000)
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: combined, Seen: ts}})

	if len(received) != 2 {
		t.Fatalf("expected 2 SIP packets, got %d", len(received))
	}
	if received[0].Tsec != uint32(ts.Unix()) || received[0].Tmsec != 818142 {
		t.Fatalf("msg0: tsec=%d tmsec=%d", received[0].Tsec, received[0].Tmsec)
	}
	if received[1].Tsec != uint32(ts.Unix()) || received[1].Tmsec != 818143 {
		t.Fatalf("msg1: tsec=%d tmsec=%d want tmsec 818143", received[1].Tsec, received[1].Tmsec)
	}
}

func TestTCPSIPDistinctTmsecAcrossSegments(t *testing.T) {
	msg := []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")

	var received []*Packet
	cb := func(pkt *Packet) { received = append(received, pkt) }

	s := &sipStream{
		net:       gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}),
		transport: gopacket.NewFlow(0, []byte{0x13, 0xc4}, []byte{0x13, 0xc4}),
		cb:        cb,
		buf:       make([]byte, 0, 4096),
	}

	ts1 := time.Unix(100, 100*1000)
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: msg, Seen: ts1}})
	ts2 := time.Unix(100, 200*1000)
	s.Reassembled([]tcpassembly.Reassembly{{Bytes: msg, Seen: ts2}})

	if len(received) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(received))
	}
	if received[0].Tmsec != 100 || received[1].Tmsec != 200 {
		t.Fatalf("tmsec: %d, %d", received[0].Tmsec, received[1].Tmsec)
	}
}
