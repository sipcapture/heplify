package main

import (
	"debug/elf"
	"fmt"
	"os"
	"runtime"

	"github.com/google/gopacket/pcap"
)

// libpcapVersion returns the version string of the libpcap (or Npcap) library
// heplify is linked with. On Windows gopacket loads wpcap.dll at run time and
// panics when Npcap is not installed, so that case is reported instead.
func libpcapVersion() (v string) {
	defer func() {
		if r := recover(); r != nil {
			v = fmt.Sprintf("unavailable (%v)", r)
		}
	}()
	return pcap.Version()
}

// linkage reports whether the running binary is statically or dynamically
// linked. On Linux this is read from the executable itself: a dynamically
// linked ELF binary has a PT_INTERP program header (the dynamic loader).
// Other platforms always link libc dynamically.
func linkage() string {
	if runtime.GOOS != "linux" {
		return "dynamic"
	}
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return elfLinkage(exe)
}

func elfLinkage(path string) string {
	f, err := elf.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return "dynamic"
		}
	}
	return "static"
}
