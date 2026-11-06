package ip6defrag

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func frag(id uint32, offset uint16, more bool, payload []byte) (*layers.IPv6, *layers.IPv6Fragment) {
	ip := &layers.IPv6{
		Version: 6,
		SrcIP:   net.ParseIP("2001:db8::1"),
		DstIP:   net.ParseIP("2001:db8::2"),
	}
	f := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolUDP,
		FragmentOffset: offset / 8,
		MoreFragments:  more,
		Identification: id,
	}
	f.Payload = payload
	return ip, f
}

func TestReassembleOutOfOrder(t *testing.T) {
	d := NewIPv6Defragmenter()
	now := time.Now()
	a := make([]byte, 16)
	b := make([]byte, 8)
	ip, f := frag(1, 16, false, b)
	if out, err := d.DefragIPv6WithTimestamp(ip, f, now); out != nil || err != nil {
		t.Fatalf("unexpected result for last fragment: %v %v", out, err)
	}
	ip, f = frag(1, 0, true, a)
	out, err := d.DefragIPv6WithTimestamp(ip, f, now)
	if err != nil || out == nil || len(out.Payload) != 24 {
		t.Fatalf("reassembly failed: out=%v err=%v", out, err)
	}
	if d.Len() != 0 {
		t.Fatalf("flow not removed after reassembly, %d left", d.Len())
	}
}

func TestOverlappingFragmentDropsDatagram(t *testing.T) {
	d := NewIPv6Defragmenter()
	now := time.Now()
	ip, f := frag(2, 16, false, make([]byte, 16))
	_, _ = d.DefragIPv6WithTimestamp(ip, f, now)
	// 8..24 overlaps 16..32
	ip, f = frag(2, 8, true, make([]byte, 16))
	if _, err := d.DefragIPv6WithTimestamp(ip, f, now); err == nil {
		t.Fatal("expected an error for an overlapping fragment")
	}
	if d.Len() != 0 {
		t.Fatalf("overlapping datagram should be dropped, %d flows left", d.Len())
	}
}

func TestFlowLimit(t *testing.T) {
	d := NewIPv6Defragmenter()
	now := time.Now()
	for i := 0; i < IPv6MaximumFlows+100; i++ {
		ip, f := frag(uint32(i), 8, true, make([]byte, 8))
		_, _ = d.DefragIPv6WithTimestamp(ip, f, now)
	}
	if d.Len() != IPv6MaximumFlows {
		t.Fatalf("expected %d flows, got %d", IPv6MaximumFlows, d.Len())
	}
	if n := d.DiscardOlderThan(now.Add(time.Second)); n != IPv6MaximumFlows {
		t.Fatalf("expected all flows discarded, got %d", n)
	}
}

func TestFlowByteLimit(t *testing.T) {
	d := NewIPv6Defragmenter()
	now := time.Now()
	// Distinct non-overlapping fragments that never complete the datagram.
	var err error
	for off := 8; off+1024 <= IPv6MaximumSize && err == nil; off += 1024 + 8 {
		ip, f := frag(3, uint16(off), true, make([]byte, 1024))
		_, err = d.DefragIPv6WithTimestamp(ip, f, now)
	}
	d.RLock()
	for _, fl := range d.ipFlows {
		if fl.Bytes > IPv6MaximumFlowBytes {
			t.Fatalf("flow buffered %d bytes, over the %d limit", fl.Bytes, IPv6MaximumFlowBytes)
		}
	}
	d.RUnlock()
}
