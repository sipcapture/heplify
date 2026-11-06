package hep

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestDecodeHEPEmptyFixedChunk(t *testing.T) {
	// Version chunk with length 6 (empty body) used to panic on body[0].
	for _, typ := range []byte{chunkVersion, chunkSrcPort, chunkTsec, chunkNodeID, chunkVlan} {
		p := []byte{'H', 'E', 'P', '3', 0, 12, 0, 0, 0, typ, 0, 6}
		if _, err := DecodeHEP(p); err == nil {
			t.Errorf("chunk type %d with empty body: want error", typ)
		}
	}
}

func TestDecodeHEPSkipsVendorChunks(t *testing.T) {
	// Vendor 0x0001, type 1 (would be "version"), 3-byte body: must be ignored.
	p := []byte{'H', 'E', 'P', '3', 0, 15, 0, 1, 0, 1, 0, 9, 'a', 'b', 'c'}
	if _, err := DecodeHEP(p); err != nil {
		t.Fatalf("vendor chunk rejected: %v", err)
	}
}

func TestEncodeNeverExceedsHEPLength(t *testing.T) {
	m := &Msg{Version: 2, SrcIP: net.IPv4(1, 2, 3, 4), DstIP: net.IPv4(5, 6, 7, 8), Payload: make([]byte, 70000)}
	b := Encode(m)
	if len(b) > MaxPacketSize {
		t.Fatalf("encoded %d bytes, max %d", len(b), MaxPacketSize)
	}
	if got := int(binary.BigEndian.Uint16(b[4:6])); got != len(b) {
		t.Fatalf("length field %d != packet length %d (stream would desync)", got, len(b))
	}
	if _, err := DecodeHEP(b); err != nil {
		t.Fatalf("truncated packet does not decode: %v", err)
	}
	if len(m.Payload) != 70000 {
		t.Fatal("Encode modified the caller's payload")
	}
	if Encode(&Msg{Version: 2, CID: make([]byte, 70000)}) != nil {
		t.Fatal("packet whose headers alone exceed the limit should not encode")
	}
}

func FuzzDecodeHEP(f *testing.F) {
	f.Add(Encode(&Msg{Version: 2, SrcIP: net.IPv4(1, 2, 3, 4), DstIP: net.IPv4(5, 6, 7, 8), Payload: []byte("x"), CID: []byte("c")}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeHEP(b) })
}
