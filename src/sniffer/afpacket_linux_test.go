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

func TestDetectLinkTypeMissingSysfs(t *testing.T) {
	orig := sysfsNetPath
	sysfsNetPath = "/nonexistent/path"
	defer func() { sysfsNetPath = orig }()

	if got := detectLinkType("eth0"); got != layers.LinkTypeEthernet {
		t.Fatalf("expected fallback to Ethernet when sysfs missing, got %v", got)
	}
}
