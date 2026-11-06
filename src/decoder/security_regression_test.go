package decoder

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Regression tests for malformed packets that used to crash or hang the
// capture goroutine. Each input is a single packet an attacker can send.

func TestParseRTCPXRMaxBlockLengthTerminates(t *testing.T) {
	// XR block length 0xFFFF: (uint16)0xFFFF+1 wrapped to 0 and looped forever.
	data := []byte{0x80, RTCPTypeXR, 0, 2, 1, 2, 3, 4, 0x01, 0, 0xff, 0xff}
	done := make(chan struct{})
	go func() {
		ParseRTCP(data)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ParseRTCP did not return: infinite loop on XR block length 0xFFFF")
	}
}

func TestParseSIPMessageHugeContentLength(t *testing.T) {
	for _, cl := range []string{"9223372036854775807", "99999999999999999999999", "2000000"} {
		msg := []byte("INVITE sip:a@b SIP/2.0\r\nContent-Length: " + cl + "\r\n\r\n")
		if _, err := parseSIPMessage(msg); err != errSIPTooLarge {
			t.Errorf("Content-Length %s: err = %v, want errSIPTooLarge", cl, err)
		}
	}
}

func TestWSPayloadHugeLength(t *testing.T) {
	// 63-bit length + mask: Offset+Length overflowed int64 and passed the check.
	data := []byte{0x81, 0xFF, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 'x'}
	if _, err := WSPayload(data); err == nil {
		t.Fatal("WSPayload accepted a frame longer than its data")
	}
	if _, err := WSFrameLen(data); err != nil && err != ErrWSHeaderLengthUnexpected {
		t.Fatalf("WSFrameLen: unexpected error %v", err)
	}
}

func TestParseDiameterUnpaddedLastAVP(t *testing.T) {
	// Last AVP has length 9 and no padding: pad (12) ran past the buffer.
	m := make([]byte, DiameterHeaderLen+9)
	binary.BigEndian.PutUint32(m[0:4], uint32(len(m))|0x01000000)
	binary.BigEndian.PutUint32(m[20:24], 1)
	m[27] = 9
	m[28] = 'a'
	msgs := ParseDiameterMessages(m)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}

	// Same inside a Grouped AVP (code 260, Vendor-Specific-Application-Id).
	g := make([]byte, DiameterHeaderLen+8+9)
	binary.BigEndian.PutUint32(g[0:4], uint32(len(g))|0x01000000)
	binary.BigEndian.PutUint32(g[20:24], 260)
	g[27] = 8 + 9
	binary.BigEndian.PutUint32(g[28:32], 266)
	g[35] = 9
	if msgs := ParseDiameterMessages(g); len(msgs) != 1 {
		t.Fatalf("grouped: got %d messages, want 1", len(msgs))
	}
}

// streamFor builds a sipStream that collects delivered payloads.
func streamFor(out *[][]byte) *sipStream {
	f := &sipStreamFactory{cb: func(p *Packet) { *out = append(*out, p.Payload) }}
	ip := layers.NewIPEndpoint([]byte{10, 0, 0, 1})
	ip2 := layers.NewIPEndpoint([]byte{10, 0, 0, 2})
	port := layers.NewTCPPortEndpoint(5060)
	port2 := layers.NewTCPPortEndpoint(40000)
	return f.New(gopacket.NewFlow(layers.EndpointIPv4, ip.Raw(), ip2.Raw()),
		gopacket.NewFlow(layers.EndpointTCPPort, port.Raw(), port2.Raw())).(*sipStream)
}

func TestSIPStreamDropsOversizedMessage(t *testing.T) {
	var got [][]byte
	s := streamFor(&got)
	s.buf = append(s.buf, []byte("INVITE sip:a@b SIP/2.0\r\nContent-Length: 9223372036854775807\r\n\r\n")...)
	s.process()
	if len(s.buf) != 0 {
		t.Fatalf("oversized message kept in buffer (%d bytes)", len(s.buf))
	}
}

func TestSIPStreamCapsUnterminatedHeaders(t *testing.T) {
	var got [][]byte
	s := streamFor(&got)
	s.buf = append(s.buf, []byte("INVITE sip:a@b SIP/2.0\r\n")...)
	for len(s.buf) <= maxStreamBuffer {
		s.buf = append(s.buf, []byte("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")...)
	}
	s.process()
	if len(s.buf) != 0 {
		t.Fatalf("unterminated headers kept growing past the cap (%d bytes)", len(s.buf))
	}
}

func TestSIPStreamWebSocketFramesSplitExactly(t *testing.T) {
	sip := []byte("OPTIONS sip:a@b SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	frame := func(p []byte) []byte { return append([]byte{0x81, byte(len(p))}, p...) }
	var got [][]byte
	s := streamFor(&got)
	// ping frame, then two SIP frames in one segment
	s.buf = append(s.buf, 0x89, 0x00)
	s.buf = append(s.buf, frame(sip)...)
	s.buf = append(s.buf, frame(sip)...)
	s.process()
	if len(got) != 2 {
		t.Fatalf("got %d SIP messages, want 2", len(got))
	}
	if len(s.buf) != 0 {
		t.Fatalf("%d bytes left in buffer", len(s.buf))
	}
}

func FuzzParseRTCP(f *testing.F) {
	f.Add([]byte{0x80, RTCPTypeXR, 0, 2, 1, 2, 3, 4, 0x07, 0, 0, 8})
	f.Add([]byte{0x81, RTCPTypeRR, 0, 7, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) { ParseRTCP(b) })
}

func FuzzParseDiameterMessages(f *testing.F) {
	f.Add([]byte{1, 0, 0, 20, 0x80, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseDiameterMessages(b)
		ExtractSCTPDiameterPayloads(b)
	})
}

func FuzzWSPayload(f *testing.F) {
	f.Add([]byte{0x81, 0x85, 1, 2, 3, 4, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = WSPayload(b)
		_, _ = WSFrameLen(b)
	})
}

func FuzzParseSIPMessage(f *testing.F) {
	f.Add([]byte("INVITE sip:a@b SIP/2.0\r\nContent-Length: 3\r\n\r\nabc"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parseSIPMessage(b)
		if err == nil && len(p) > len(b) {
			t.Fatalf("message longer than input")
		}
	})
}

func FuzzExtractCID(f *testing.F) {
	f.Add([]byte("INVITE sip:a SIP/2.0\r\nCall-ID: x\r\nContent-Type: application/sdp\r\n\r\nc=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/AVP 0\r\na=rtcp:4001 IN IP4 1.2.3.4\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ExtractCID([]byte{1, 2, 3, 4}, 5060, []byte{5, 6, 7, 8}, 5060, b)
	})
}
