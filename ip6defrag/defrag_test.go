package ip6defrag

import (
	"testing"

	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func generateFragment(id uint32, offset uint16, moreFragments bool, payload []byte) (layers.IPv6, layers.IPv6Fragment) {
	ip := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		SrcIP:      []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		DstIP:      []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2},
	}
	ipFragment := layers.IPv6Fragment{
		Identification: id,
		FragmentOffset: offset,
		MoreFragments:  moreFragments,
		NextHeader:     layers.IPProtocolTCP,
	}
	ipFragment.Payload = payload
	return ip, ipFragment
}

func TestNotCompleteFrag(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	out, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.NoError(t, err)
	assert.Nil(t, out, "Packet defragmented while MoreFragments flag was set")
}

func TestTwoFrag(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	_, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.NoError(t, err)

	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8, 9, 10})
	out, err := defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.NotNil(t, out, "Packet not defragmented after sending all fragments")

	assert.Equal(t, out.Payload, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "Payload not reassembled correctly")
	assert.Equal(t, out.NextHeader, layers.IPProtocolTCP, "NextHeader not copied correctly to final ip packet")
	assert.Equal(t, ip.SrcIP, out.SrcIP)
	assert.Equal(t, ip.DstIP, out.DstIP)
	assert.Equal(t, ip.Version, out.Version)
}

func TestThreeFrag(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(0, 1, true, []byte{8, 9, 10, 11, 12, 13, 14, 15})
	ip3, ipFragment3 := generateFragment(0, 2, false, []byte{16, 17})

	out, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.Nil(t, out, "Packet defragged while missing fragments")
	assert.NoError(t, err)

	out, err = defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.Nil(t, out, "Packet defragged while missing fragments")
	assert.NoError(t, err)

	out, err = defrag.DefragIPv6(&ip3, &ipFragment3)
	assert.NoError(t, err)

	assert.NotNil(t, out, "Packet not defragmented after sending all fragments")
	assert.Equal(t, out.Payload, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, "Payload not reassembled correctly")
}

func TestThreeFragNotOrdered(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(0, 1, true, []byte{8, 9, 10, 11, 12, 13, 14, 15})
	ip3, ipFragment3 := generateFragment(0, 2, false, []byte{16, 17})

	out, err := defrag.DefragIPv6(&ip3, &ipFragment3)
	assert.Nil(t, out, "Packet defragged while missing fragments")
	assert.NoError(t, err)

	out, err = defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.Nil(t, out, "Packet defragged while missing fragments")
	assert.NoError(t, err)

	out, err = defrag.DefragIPv6(&ip, &ipFragment)
	assert.NoError(t, err)

	assert.NotNil(t, out, "Packet not defragmented after sending all fragments")
	assert.Equal(t, out.Payload, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, "Payload not reassembled correctly")
}

func TestNotAssembleDifferentID(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(1, 1, false, []byte{8, 9, 10})

	defrag.DefragIPv6(&ip, &ipFragment)

	out, err := defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.Nil(t, out, "Packet defragmented from different id")
	assert.NoError(t, err)
}

func TestNotAssembleDifferentFlow(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8, 9, 10})
	ip2.SrcIP[0] = 255

	defrag.DefragIPv6(&ip, &ipFragment)

	out, err := defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.Nil(t, out, "Packet defragmented from different flow")
	assert.NoError(t, err)
}

func TestDiscardOldFlows(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8})

	defrag.DefragIPv6WithTimestamp(&ip, &ipFragment, time.Now().Add(-time.Hour))
	defrag.DiscardOlderThan(time.Now())

	out, _ := defrag.DefragIPv6WithTimestamp(&ip2, &ipFragment2, time.Now())
	assert.Nil(t, out, "Packet defragged after discarding.")
}

func TestNotDiscardFlows(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8})

	defrag.DefragIPv6WithTimestamp(&ip, &ipFragment, time.Now())
	defrag.DiscardOlderThan(time.Now().Add(-time.Hour))

	out, _ := defrag.DefragIPv6WithTimestamp(&ip2, &ipFragment2, time.Now())
	assert.NotNil(t, out, "Packet defragged after discarding.")
}

func TestNotAssembleOverlappingFragments(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23})

	defrag.DefragIPv6WithTimestamp(&ip, &ipFragment, time.Now())
	out, _ := defrag.DefragIPv6WithTimestamp(&ip2, &ipFragment2, time.Now())

	assert.Nil(t, out, "Overlapping fragments not defragged")
}

func TestDuplicateFragments(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 0, true, []byte{0, 1, 2, 3, 4, 5, 6, 7})
	_, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.NoError(t, err)

	// Duplicate
	_, err = defrag.DefragIPv6(&ip, &ipFragment)
	assert.NoError(t, err)

	ip2, ipFragment2 := generateFragment(0, 1, false, []byte{8, 9, 10})
	out, err := defrag.DefragIPv6(&ip2, &ipFragment2)
	assert.NotNil(t, out, "Packet not defragmented after sending duplicated fragment")
	assert.Equal(t, out.Payload, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "Payload not reassembled correctly")
}

func TestSecurityCheckFragmentOffset(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	ip, ipFragment := generateFragment(0, 8191+1, true, []byte{})
	_, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.Error(t, err)
}

func TestSecurityCheckOversized(t *testing.T) {
	t.Parallel()
	defrag := NewIPv6Defragmenter()
	payload := make([]byte, 65535)
	payload[65534] = 0 // Force length
	ip, ipFragment := generateFragment(0, 20, true, payload)
	_, err := defrag.DefragIPv6(&ip, &ipFragment)
	assert.Error(t, err)
}
