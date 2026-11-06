package decoder

import (
	"fmt"
	"testing"
	"time"
)

func TestTTLCacheBounded(t *testing.T) {
	c := newTTLCache(time.Minute, 100)
	for i := 0; i < 1000; i++ {
		c.Set(fmt.Sprintf("k%d", i), []byte("v"))
	}
	if n := c.Len(); n > 100 {
		t.Fatalf("cache grew to %d entries, limit is 100", n)
	}
	if _, ok := c.Get("k999"); !ok {
		t.Fatal("most recent entry should be present")
	}
}

func TestTTLCacheCopiesValue(t *testing.T) {
	c := newTTLCache(time.Minute, 10)
	buf := []byte("call-1")
	c.Set("k", buf)
	copy(buf, "XXXXXX")
	got, _ := c.Get("k")
	if string(got) != "call-1" {
		t.Fatalf("cached value changed with the source buffer: %q", got)
	}
}

func TestIP4FragmentFlowLimit(t *testing.T) {
	d := NewDecoder(1)
	now := time.Now()
	for i := 0; i < ip4MaxFragFlows+10; i++ {
		k := ip4FragKey{id: uint16(i), src: [4]byte{10, 0, byte(i >> 8), 1}}
		d.trackIP4Fragment(k, 100, now)
	}
	if len(d.ip4Flows) != ip4MaxFragFlows {
		t.Fatalf("expected %d tracked flows, got %d", ip4MaxFragFlows, len(d.ip4Flows))
	}
	k := ip4FragKey{id: 1}
	d2 := NewDecoder(1)
	for i := 0; ; i++ {
		if !d2.trackIP4Fragment(k, 1480, now) {
			if i*1480 > ip4MaxFlowBytes {
				t.Fatalf("flow accepted %d bytes, limit is %d", i*1480, ip4MaxFlowBytes)
			}
			break
		}
	}
	d.DiscardStaleFragments(now.Add(time.Second))
	if len(d.ip4Flows) != 0 {
		t.Fatalf("stale flows not discarded: %d left", len(d.ip4Flows))
	}
}

func TestSDPMediaLimit(t *testing.T) {
	body := "v=0\r\nc=IN IP4 10.9.9.9\r\n"
	for i := 0; i < 100; i++ {
		body += fmt.Sprintf("m=audio %d RTP/AVP 0\r\n", 40000+i*2)
	}
	msg := "INVITE sip:a@b SIP/2.0\r\nCall-ID: media-limit\r\nContent-Type: application/sdp\r\n\r\n" + body
	before := cidCache.Len()
	ExtractCID([]byte{10, 9, 9, 9}, 5060, []byte{10, 0, 0, 2}, 5060, []byte(msg))
	added := cidCache.Len() - before
	if added > maxSDPMedia {
		t.Fatalf("one SDP added %d cache entries, limit is %d", added, maxSDPMedia)
	}
	if added == 0 {
		t.Fatal("expected some media to be cached")
	}
}
