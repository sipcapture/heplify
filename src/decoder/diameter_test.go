package decoder

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

func buildDiameterMessage(cmd uint32, appID uint32, flags byte, avps []byte) []byte {
	msgLen := DiameterHeaderLen + len(avps)
	buf := make([]byte, msgLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(msgLen)&0x00ffffff)
	buf[0] = 0x01
	buf[4] = flags
	buf[5] = byte(cmd >> 16)
	buf[6] = byte(cmd >> 8)
	buf[7] = byte(cmd)
	binary.BigEndian.PutUint32(buf[8:12], appID)
	binary.BigEndian.PutUint32(buf[12:16], 0x11223344)
	binary.BigEndian.PutUint32(buf[16:20], 0xaabbccdd)
	copy(buf[20:], avps)
	return buf
}

func buildAVP(code uint32, flags byte, data []byte) []byte {
	payloadStart := 8
	length := 8 + len(data)
	buf := make([]byte, length)
	binary.BigEndian.PutUint32(buf[0:4], code)
	buf[4] = flags
	buf[5] = byte(length >> 16)
	buf[6] = byte(length >> 8)
	buf[7] = byte(length)
	copy(buf[payloadStart:], data)
	// pad to 4
	pad := length % 4
	if pad != 0 {
		buf = append(buf, make([]byte, 4-pad)...)
	}
	return buf
}

func TestParseDiameterSessionID(t *testing.T) {
	session := []byte("host.example;1234;5678")
	avp := buildAVP(263, 0x40, session) // Session-Id, M flag
	msg := buildDiameterMessage(280, 0, 0x80, avp)

	parsed := ParseDiameterMessages(msg)
	if len(parsed) != 1 {
		t.Fatalf("expected 1 message, got %d", len(parsed))
	}
	if string(parsed[0].CID) != string(session) {
		t.Fatalf("CID = %q, want %q", parsed[0].CID, session)
	}
	var report DiameterReport
	if err := json.Unmarshal(parsed[0].JSON, &report); err != nil {
		t.Fatal(err)
	}
	if report.Command != 280 {
		t.Fatalf("command = %d, want 280", report.Command)
	}
	if report.Type != "Request" {
		t.Fatalf("type = %q, want Request", report.Type)
	}
	if len(report.AVPs) != 1 || report.AVPs[0].Name != "Session-Id" {
		t.Fatalf("unexpected AVPs: %+v", report.AVPs)
	}
}

func TestParseDiameterMultiMessage(t *testing.T) {
	a := buildDiameterMessage(280, 0, 0x80, buildAVP(263, 0x40, []byte("a")))
	b := buildDiameterMessage(280, 0, 0x00, buildAVP(263, 0x40, []byte("b")))
	parsed := ParseDiameterMessages(append(a, b...))
	if len(parsed) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed))
	}
	if string(parsed[0].CID) != "a" || string(parsed[1].CID) != "b" {
		t.Fatalf("CIDs = %q,%q", parsed[0].CID, parsed[1].CID)
	}
}

func TestExtractSCTPDiameterPayloads(t *testing.T) {
	diam := buildDiameterMessage(280, 0, 0x80, buildAVP(263, 0x40, []byte("sctp-sess")))
	// DATA chunk: type=0, flags=3 (B+E), length=16+len(diam)
	chunkLen := 16 + len(diam)
	chunk := make([]byte, chunkLen)
	chunk[0] = 0 // DATA
	chunk[1] = 0x03
	binary.BigEndian.PutUint16(chunk[2:4], uint16(chunkLen))
	copy(chunk[16:], diam)

	payloads := ExtractSCTPDiameterPayloads(chunk)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	msgs := ParseDiameterFromPacket(0x84, chunk)
	if len(msgs) != 1 || string(msgs[0].CID) != "sctp-sess" {
		t.Fatalf("unexpected parse: %+v", msgs)
	}
}

func TestIsDiameterPayload(t *testing.T) {
	if IsDiameterPayload([]byte("INVITE sip:a SIP/2.0")) {
		t.Fatal("SIP must not look like Diameter")
	}
	msg := buildDiameterMessage(257, 0, 0x80, nil)
	if !IsDiameterPayload(msg) {
		t.Fatal("expected Diameter detection")
	}
}

func TestDiameterMessageLengthTruncated(t *testing.T) {
	msg := buildDiameterMessage(280, 0, 0x80, buildAVP(263, 0x40, []byte("x")))
	truncated := msg[:10]
	if got := ParseDiameterMessages(truncated); len(got) != 0 {
		t.Fatalf("expected 0 messages for truncated input, got %d", len(got))
	}
}
