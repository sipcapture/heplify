package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestLibpcapVersion(t *testing.T) {
	v := libpcapVersion()
	if !strings.Contains(strings.ToLower(v), "pcap") && !strings.HasPrefix(v, "unavailable") {
		t.Fatalf("unexpected libpcap version string %q", v)
	}
}

func TestLinkage(t *testing.T) {
	switch l := linkage(); l {
	case "static", "dynamic":
	default:
		t.Fatalf("linkage() = %q, want static or dynamic", l)
	}
}

func TestElfLinkage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF only")
	}
	if got := elfLinkage("/nonexistent"); got != "unknown" {
		t.Fatalf("missing file: got %q, want unknown", got)
	}
	// A text file is not ELF.
	f, err := os.CreateTemp(t.TempDir(), "notelf")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("#!/bin/sh\n")
	f.Close()
	if got := elfLinkage(f.Name()); got != "unknown" {
		t.Fatalf("non-ELF file: got %q, want unknown", got)
	}
}
