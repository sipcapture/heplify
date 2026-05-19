package decoder

import (
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestDiscardStaleFragments_disabled(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	d.DisableDefrag()
	v4, v6 := d.DiscardStaleFragments(time.Now())
	if v4 != 0 || v6 != 0 {
		t.Fatalf("expected 0,0 got %d,%d", v4, v6)
	}
}

func TestDiscardStaleFragments_noStale(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	cutoff := time.Now().Add(IPFragmentFlushInterval)
	v4, v6 := d.DiscardStaleFragments(cutoff)
	if v4 != 0 || v6 != 0 {
		t.Fatalf("expected 0,0 got %d,%d", v4, v6)
	}
}
