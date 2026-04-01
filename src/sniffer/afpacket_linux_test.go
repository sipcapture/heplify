//go:build linux

package sniffer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestDetectLinkType(t *testing.T) {
	tests := []struct {
		arphrd   string
		device   string
		wantType layers.LinkType
	}{
		{"1", "eth0", layers.LinkTypeEthernet},   // ARPHRD_ETHER
		{"772", "lo", layers.LinkTypeEthernet},   // ARPHRD_LOOPBACK
		{"768", "tunl0", layers.LinkTypeRaw},      // ARPHRD_TUNNEL (ipip)
		{"776", "sit0", layers.LinkTypeRaw},       // ARPHRD_SIT
		{"778", "gre0", layers.LinkTypeRaw},       // ARPHRD_IPGRE
		{"823", "ip6gre0", layers.LinkTypeRaw},    // ARPHRD_IP6GRE
		{"65534", "dummy0", layers.LinkTypeRaw},   // ARPHRD_NONE
		{"999", "unknown0", layers.LinkTypeEthernet}, // unknown — safe fallback
	}

	tmp := t.TempDir()
	orig := sysfsNetPath
	sysfsNetPath = tmp
	defer func() { sysfsNetPath = orig }()

	for _, tc := range tests {
		ifDir := filepath.Join(tmp, tc.device)
		if err := os.MkdirAll(ifDir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", ifDir, err)
		}
		if err := os.WriteFile(filepath.Join(ifDir, "type"), []byte(tc.arphrd+"\n"), 0o644); err != nil {
			t.Fatalf("write type for %s: %v", tc.device, err)
		}

		got := detectLinkType(tc.device)
		if got != tc.wantType {
			t.Errorf("detectLinkType(%q, arphrd=%s): got %v, want %v",
				tc.device, tc.arphrd, got, tc.wantType)
		}
	}
}

func TestDetectLinkTypeAny(t *testing.T) {
	if got := detectLinkType("any"); got != layers.LinkTypeEthernet {
		t.Fatalf("detectLinkType(\"any\") = %v, want Ethernet", got)
	}
}

func TestSetInterfacePromiscNonExistent(t *testing.T) {
	// setInterfacePromisc should return an error for a non-existent interface.
	err := setInterfacePromisc("__no_such_iface__", true)
	if err == nil {
		t.Fatal("expected error for non-existent interface, got nil")
	}
}

func TestApplyPromiscNoRoot(t *testing.T) {
	// applyPromisc for a non-existent device must not panic; it logs a warning
	// and leaves promiscIfaces empty.
	h := &afpacketHandle{}
	h.applyPromisc("__no_such_iface__", nil)
	if len(h.promiscIfaces) != 0 {
		t.Fatalf("expected empty promiscIfaces, got %v", h.promiscIfaces)
	}
}

func TestApplyPromiscAnyEmptyList(t *testing.T) {
	// With device="any" and an empty promiscIfaces list, applyPromisc must not
	// touch any interface (it emits a warning instead).
	h := &afpacketHandle{}
	h.applyPromisc("any", nil)
	if len(h.promiscIfaces) != 0 {
		t.Fatalf("expected no interfaces set, got %v", h.promiscIfaces)
	}
}

func TestApplyPromiscAnyWithList(t *testing.T) {
	// With device="any" and a non-empty list, only the listed interfaces should
	// be attempted. Non-existent ones produce a warning but no panic.
	h := &afpacketHandle{}
	h.applyPromisc("any", []string{"__no_such_iface_a__", "__no_such_iface_b__"})
	// Both will fail (no such interface), so promiscIfaces stays empty.
	if len(h.promiscIfaces) != 0 {
		t.Fatalf("expected empty promiscIfaces for non-existent interfaces, got %v", h.promiscIfaces)
	}
}

func TestDetectLinkTypeMissingSysfs(t *testing.T) {
	orig := sysfsNetPath
	sysfsNetPath = "/nonexistent/path"
	defer func() { sysfsNetPath = orig }()

	if got := detectLinkType("eth0"); got != layers.LinkTypeEthernet {
		t.Fatalf("expected fallback to Ethernet when sysfs missing, got %v", got)
	}
}
