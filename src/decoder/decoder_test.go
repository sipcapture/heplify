package decoder

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestBoolToUint8(t *testing.T) {
	if got := boolToUint8(true); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	if got := boolToUint8(false); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestDecodeInvalidPacketReturnsNil(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	pkt, err := d.Decode([]byte{0x01, 0x02, 0x03}, ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt != nil {
		t.Fatalf("expected nil packet for invalid input")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

var (
	testSrcMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	testDstMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	testSrcIP4 = net.ParseIP("10.0.0.1").To4()
	testDstIP4 = net.ParseIP("10.0.0.2").To4()
	testSrcIP6 = net.ParseIP("2001:db8::1")
	testDstIP6 = net.ParseIP("2001:db8::2")
)

// buildUDPDatagram returns a raw UDP datagram (header + payload) with zero checksum.
func buildUDPDatagram(dstPort uint16, payload []byte) []byte {
	const srcPort = 5060
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// checksum = 0 (disabled)
	copy(udp[8:], payload)
	return udp
}

// buildIPv4Frag builds a complete Ethernet+IPv4 packet carrying a fragment.
// fragmentOffset is in 8-byte units (matches the IPv4 header field).
func buildIPv4Frag(t *testing.T, fragID uint16, fragOffset uint16, moreFragments bool, payload []byte) []byte {
	t.Helper()
	flags := layers.IPv4Flag(0)
	if moreFragments {
		flags = layers.IPv4MoreFragments
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version:    4,
			IHL:        5,
			Protocol:   layers.IPProtocolUDP,
			TTL:        64,
			Id:         fragID,
			SrcIP:      testSrcIP4,
			DstIP:      testDstIP4,
			Flags:      flags,
			FragOffset: fragOffset,
		},
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("buildIPv4Frag: %v", err)
	}
	return buf.Bytes()
}

// buildIPv6Frag builds a complete Ethernet+IPv6 packet carrying an IPv6 fragment extension header.
// fragOffset is in 8-byte units.
func buildIPv6Frag(t *testing.T, fragID uint32, fragOffset uint16, moreFragments bool, nextProto byte, payload []byte) []byte {
	t.Helper()
	// 8-byte IPv6 Fragment extension header (RFC 2460 §4.5)
	fragHdr := make([]byte, 8)
	fragHdr[0] = nextProto
	fragHdr[1] = 0
	offsetAndFlags := fragOffset << 3
	if moreFragments {
		offsetAndFlags |= 1
	}
	binary.BigEndian.PutUint16(fragHdr[2:4], offsetAndFlags)
	binary.BigEndian.PutUint32(fragHdr[4:8], fragID)

	fragPayload := append(fragHdr, payload...)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv6},
		&layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolIPv6Fragment,
			HopLimit:   64,
			SrcIP:      testSrcIP6,
			DstIP:      testDstIP6,
		},
		gopacket.Payload(fragPayload),
	); err != nil {
		t.Fatalf("buildIPv6Frag: %v", err)
	}
	return buf.Bytes()
}

// ─── IPv4 defragmentation ─────────────────────────────────────────────────────

func TestIPv4Defragmentation(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	// UDP payload must be sized so the split boundary is a multiple of 8.
	// udpDatagram = 8-byte header + 40-byte payload = 48 bytes; split at 24.
	udpPayload := []byte("SIP/2.0 200 OK defrag test payload!12345")
	udpDatagram := buildUDPDatagram(5060, udpPayload)
	const splitAt = 24 // multiple of 8 → fragOffset = 3
	chunk1 := udpDatagram[:splitAt]
	chunk2 := udpDatagram[splitAt:]

	// Fragment 1: MF=1, offset=0 — should be buffered.
	pkt, err := d.Decode(buildIPv4Frag(t, 0xAB01, 0, true, chunk1), ci)
	if err != nil {
		t.Fatalf("frag1 decode error: %v", err)
	}
	if pkt != nil {
		t.Fatal("frag1: expected nil (buffered), got assembled packet")
	}

	// Fragment 2: MF=0, offset=splitAt/8 — triggers reassembly.
	pkt, err = d.Decode(buildIPv4Frag(t, 0xAB01, splitAt/8, false, chunk2), ci)
	if err != nil {
		t.Fatalf("frag2 decode error: %v", err)
	}
	if pkt == nil {
		t.Fatal("frag2: expected assembled packet, got nil")
	}
	if pkt.Protocol != 0x11 {
		t.Fatalf("expected UDP (0x11), got 0x%02x", pkt.Protocol)
	}
	if pkt.SrcPort != 5060 || pkt.DstPort != 5060 {
		t.Fatalf("expected ports 5060/5060, got %d/%d", pkt.SrcPort, pkt.DstPort)
	}
	if string(pkt.Payload) != string(udpPayload) {
		t.Fatalf("payload mismatch:\ngot:  %q\nwant: %q", pkt.Payload, udpPayload)
	}
}

func TestIPv4DefragDisabled(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	d.DisableDefrag()
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	udpDatagram := buildUDPDatagram(5060, []byte("SIP/2.0 200 OK defrag test payload!12345"))
	const splitAt = 24
	chunk1 := udpDatagram[:splitAt]
	chunk2 := udpDatagram[splitAt:]

	// With defrag disabled, both fragments are dropped (no transport layer decoded).
	for i, data := range [][]byte{
		buildIPv4Frag(t, 0xCC01, 0, true, chunk1),
		buildIPv4Frag(t, 0xCC01, splitAt/8, false, chunk2),
	} {
		pkt, err := d.Decode(data, ci)
		if err != nil {
			t.Fatalf("frag%d: unexpected error: %v", i+1, err)
		}
		if pkt != nil {
			t.Fatalf("frag%d: defrag disabled, expected nil, got packet", i+1)
		}
	}
}

// ─── IPv6 defragmentation ─────────────────────────────────────────────────────

func TestIPv6Defragmentation(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	udpPayload := []byte("SIP/2.0 200 OK defrag test payload!12345")
	udpDatagram := buildUDPDatagram(5060, udpPayload)
	const splitAt = 24 // multiple of 8
	chunk1 := udpDatagram[:splitAt]
	chunk2 := udpDatagram[splitAt:]

	// Fragment 1: MF=1, offset=0.
	pkt, err := d.Decode(buildIPv6Frag(t, 0xDEADBEEF, 0, true, 0x11, chunk1), ci)
	if err != nil {
		t.Fatalf("frag1 decode error: %v", err)
	}
	if pkt != nil {
		t.Fatal("frag1: expected nil (buffered), got assembled packet")
	}

	// Fragment 2: MF=0, offset=splitAt/8.
	pkt, err = d.Decode(buildIPv6Frag(t, 0xDEADBEEF, splitAt/8, false, 0x11, chunk2), ci)
	if err != nil {
		t.Fatalf("frag2 decode error: %v", err)
	}
	if pkt == nil {
		t.Fatal("frag2: expected assembled packet, got nil")
	}
	if pkt.Protocol != 0x11 {
		t.Fatalf("expected UDP (0x11), got 0x%02x", pkt.Protocol)
	}
	if pkt.SrcPort != 5060 || pkt.DstPort != 5060 {
		t.Fatalf("expected ports 5060/5060, got %d/%d", pkt.SrcPort, pkt.DstPort)
	}
	if string(pkt.Payload) != string(udpPayload) {
		t.Fatalf("payload mismatch:\ngot:  %q\nwant: %q", pkt.Payload, udpPayload)
	}
}

// ─── decodeTransport helper ───────────────────────────────────────────────────

func TestDecodeTransportUDP(t *testing.T) {
	payload := buildUDPDatagram(5061, []byte("hello"))
	proto, sp, dp, flags, data, ok := decodeTransport(layers.IPProtocolUDP, payload)
	if !ok {
		t.Fatal("decodeTransport: expected ok=true")
	}
	if proto != 0x11 {
		t.Fatalf("expected proto 0x11, got 0x%02x", proto)
	}
	if sp != 5060 || dp != 5061 {
		t.Fatalf("expected 5060/5061, got %d/%d", sp, dp)
	}
	if flags != 0 {
		t.Fatalf("expected flags=0, got %d", flags)
	}
	if string(data) != "hello" {
		t.Fatalf("payload mismatch: %q", data)
	}
}

func TestDecodeTransportUnknownProto(t *testing.T) {
	_, _, _, _, _, ok := decodeTransport(layers.IPProtocolICMPv6, []byte{0, 1, 2, 3})
	if ok {
		t.Fatal("expected ok=false for unknown protocol")
	}
}

// ─── raw-IP link type (ipip / sit tunnel interfaces) ─────────────────────────

// buildRawIPv4UDP builds a raw IPv4+UDP datagram (no Ethernet header).
func buildRawIPv4UDP(t *testing.T, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Protocol: layers.IPProtocolUDP,
			TTL:      64,
			SrcIP:    testSrcIP4,
			DstIP:    testDstIP4,
		},
		&layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)},
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("buildRawIPv4UDP: %v", err)
	}
	return buf.Bytes()
}

func TestRawIPv4LinkType(t *testing.T) {
	d := NewDecoder(layers.LinkTypeRaw)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	data := buildRawIPv4UDP(t, 5060, 5060, []byte("INVITE sip:bob@example.com SIP/2.0\r\n"))
	pkt, err := d.Decode(data, ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt == nil {
		t.Fatal("expected decoded packet, got nil")
	}
	if pkt.Protocol != 0x11 {
		t.Fatalf("expected UDP (0x11), got 0x%02x", pkt.Protocol)
	}
	if pkt.SrcPort != 5060 || pkt.DstPort != 5060 {
		t.Fatalf("expected ports 5060/5060, got %d/%d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.Version != 0x02 {
		t.Fatalf("expected IPv4 version 0x02, got 0x%02x", pkt.Version)
	}
}

func TestRawIPv4FromPcap(t *testing.T) {
	handle, err := pcap.OpenOffline("testdata/ipip0.pcap")
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer handle.Close()

	// Use the link type reported by the pcap file — must produce a working decoder.
	d := NewDecoder(handle.LinkType())
	decoded := 0

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			break // EOF or error
		}
		pkt, decErr := d.Decode(data, ci)
		if decErr != nil {
			t.Errorf("decode error: %v", decErr)
			continue
		}
		if pkt == nil {
			t.Errorf("packet %d: decode returned nil (expected UDP/SIP)", decoded+1)
			continue
		}
		if pkt.Protocol != 0x11 {
			t.Errorf("packet %d: expected UDP, got proto 0x%02x", decoded+1, pkt.Protocol)
		}
		decoded++
	}

	const wantPackets = 8
	if decoded != wantPackets {
		t.Fatalf("decoded %d packets, want %d", decoded, wantPackets)
	}
}

// ─── GRE with IP payload ──────────────────────────────────────────────────────

// buildGREIPv4UDP builds an Ethernet+IPv4+GRE+IPv4+UDP packet.
func buildGREIPv4UDP(t *testing.T, innerSrcPort, innerDstPort uint16, payload []byte) []byte {
	t.Helper()

	// Build inner IPv4+UDP datagram first.
	innerBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(innerBuf, gopacket.SerializeOptions{FixLengths: true},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Protocol: layers.IPProtocolUDP,
			TTL:      64,
			SrcIP:    testSrcIP4,
			DstIP:    testDstIP4,
		},
		&layers.UDP{SrcPort: layers.UDPPort(innerSrcPort), DstPort: layers.UDPPort(innerDstPort)},
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("buildGREIPv4UDP inner: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Protocol: layers.IPProtocolGRE,
			TTL:      64,
			SrcIP:    net.ParseIP("10.1.0.1").To4(),
			DstIP:    net.ParseIP("10.1.0.2").To4(),
		},
		&layers.GRE{Protocol: layers.EthernetTypeIPv4},
		gopacket.Payload(innerBuf.Bytes()),
	); err != nil {
		t.Fatalf("buildGREIPv4UDP outer: %v", err)
	}
	return buf.Bytes()
}

func TestGREWithIPv4Payload(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	payload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n")
	data := buildGREIPv4UDP(t, 5060, 5060, payload)

	pkt, err := d.Decode(data, ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt == nil {
		t.Fatal("expected decoded inner packet from GRE, got nil")
	}
	if pkt.Protocol != 0x11 {
		t.Fatalf("expected UDP (0x11), got 0x%02x", pkt.Protocol)
	}
	if pkt.SrcPort != 5060 || pkt.DstPort != 5060 {
		t.Fatalf("expected ports 5060/5060, got %d/%d", pkt.SrcPort, pkt.DstPort)
	}
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload mismatch: got %q", pkt.Payload)
	}
}

// ─── GRE with ERSPAN Type II payload (regression: issue #336) ────────────────

// buildGREERSPANTypeII builds an Ethernet+IPv4+GRE(0x88BE)+ERSPAN_II+Ethernet+IPv4+UDP packet.
// ERSPAN Type II header is 8 bytes: Version+VLAN (2B) | CoS+T+SpanID (2B) | Reserved+Index (4B).
func buildGREERSPANTypeII(t *testing.T, vlan uint16, innerSrcPort, innerDstPort uint16, payload []byte) []byte {
	t.Helper()

	// Inner Ethernet+IPv4+UDP frame.
	innerBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(innerBuf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, Protocol: layers.IPProtocolUDP, TTL: 64, SrcIP: testSrcIP4, DstIP: testDstIP4},
		&layers.UDP{SrcPort: layers.UDPPort(innerSrcPort), DstPort: layers.UDPPort(innerDstPort)},
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("buildGREERSPANTypeII inner: %v", err)
	}

	// 8-byte ERSPAN Type II header.
	// Byte 0-1: Version=1 (4 bits, upper) + VLAN (12 bits)
	// Byte 2-3: CoS=0, Encap=0, T=0, SpanID=1
	// Byte 4-7: Reserved=0, Index=0
	erspan := make([]byte, 8)
	binary.BigEndian.PutUint16(erspan[0:2], (1<<12)|vlan)
	binary.BigEndian.PutUint16(erspan[2:4], 0x0001) // SpanID=1
	binary.BigEndian.PutUint32(erspan[4:8], 0)

	erspan = append(erspan, innerBuf.Bytes()...)

	// Outer Ethernet+IPv4+GRE(0x88BE) wrapping the ERSPAN payload.
	outerBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(outerBuf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Protocol: layers.IPProtocolGRE,
			TTL:      64,
			SrcIP:    net.ParseIP("192.168.1.1").To4(),
			DstIP:    net.ParseIP("192.168.1.2").To4(),
		},
		&layers.GRE{Protocol: layers.EthernetTypeERSPAN},
		gopacket.Payload(erspan),
	); err != nil {
		t.Fatalf("buildGREERSPANTypeII outer: %v", err)
	}
	return outerBuf.Bytes()
}

func TestGREWithERSPANTypeII(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now()}

	payload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n")
	const vlan = 100
	data := buildGREERSPANTypeII(t, vlan, 5060, 5060, payload)

	pkt, err := d.Decode(data, ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt == nil {
		t.Fatal("ERSPAN Type II: expected decoded inner packet from GRE(0x88BE), got nil (regression: issue #336)")
	}
	if pkt.Protocol != 0x11 {
		t.Fatalf("expected UDP (0x11), got 0x%02x", pkt.Protocol)
	}
	if pkt.SrcPort != 5060 || pkt.DstPort != 5060 {
		t.Fatalf("expected ports 5060/5060, got %d/%d", pkt.SrcPort, pkt.DstPort)
	}
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload mismatch: got %q", pkt.Payload)
	}
	if pkt.Vlan != vlan {
		t.Fatalf("expected VLAN %d from ERSPAN header, got %d", vlan, pkt.Vlan)
	}
}

// TestTCPSIPMidStreamResync verifies that a SIP message delivered with
// r.Skip != 0 (half-open stream — heplify started after the SYN) is still
// decoded rather than silently dropped.
func TestTCPSIPMidStreamResync(t *testing.T) {
	sipMsg := []byte("SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TCP 10.0.0.1;branch=z9hG4bK1\r\n" +
		"From: <sip:alice@example.com>;tag=1\r\n" +
		"To: <sip:bob@example.com>;tag=2\r\n" +
		"Call-ID: mid-stream-test@10.0.0.1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")

	var received []*Packet
	cb := func(pkt *Packet) { received = append(received, pkt) }

	s := &sipStream{
		net:       gopacket.NewFlow(0, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}),
		transport: gopacket.NewFlow(0, []byte{0x13, 0xc4}, []byte{0x13, 0xc4}), // 5060→5060
		cb:        cb,
		buf:       make([]byte, 0, 4096),
	}

	ts := time.Now()
	// Simulate what gopacket sends when heplify missed the SYN:
	// r.Skip != 0 and r.Bytes contains the start of the SIP response.
	s.Reassembled([]tcpassembly.Reassembly{
		{
			Bytes: sipMsg,
			Skip:  -1, // non-zero → gap / half-open
			Seen:  ts,
		},
	})

	if len(received) != 1 {
		t.Fatalf("expected 1 SIP packet, got %d (mid-stream resync failed)", len(received))
	}
}
