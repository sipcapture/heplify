//go:build linux

package sniffer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// sysfsNetPath is the base path for network interface attributes.
// Overridden in tests.
var sysfsNetPath = "/sys/class/net"

// detectLinkType reads the ARPHRD hardware type from sysfs and maps it to the
// corresponding gopacket LinkType. Falls back to Ethernet on any error or for
// unknown types so that existing behaviour is preserved.
//
// For the "any" pseudo-interface AF_PACKET delivers raw frames in their native
// framing (Ethernet for most physical interfaces). SOCK_DGRAM + TPACKET_V3
// does not prepend SLL headers in the ring buffer, so we stay with Ethernet
// as the root link type for "any". Tunnel interfaces should be captured
// explicitly (e.g. -i tunl0) where detectLinkType returns LinkTypeRaw.
func detectLinkType(device string) layers.LinkType {
	if device == "" || device == "any" {
		return layers.LinkTypeEthernet
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%s/type", sysfsNetPath, device))
	if err != nil {
		return layers.LinkTypeEthernet
	}
	arphrd, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return layers.LinkTypeEthernet
	}
	switch arphrd {
	case 1: // ARPHRD_ETHER
		return layers.LinkTypeEthernet
	case 772: // ARPHRD_LOOPBACK
		return layers.LinkTypeEthernet
	case 768: // ARPHRD_TUNNEL  (ipip / tunl0)
		return layers.LinkTypeRaw
	case 776: // ARPHRD_SIT     (sit0 — IPv6-in-IPv4)
		return layers.LinkTypeRaw
	case 778: // ARPHRD_IPGRE   (GRE over IPv4)
		return layers.LinkTypeRaw
	case 823: // ARPHRD_IP6GRE  (GRE over IPv6)
		return layers.LinkTypeRaw
	case 65534: // ARPHRD_NONE
		return layers.LinkTypeRaw
	default:
		return layers.LinkTypeEthernet
	}
}

// ifreqFlags matches the layout of struct ifreq as used by SIOCGIFFLAGS /
// SIOCSIFFLAGS (first 16 bytes = name, next 2 bytes = flags).
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [22]byte // padding to sizeof(struct ifreq) = 40
}

// setInterfacePromisc enables or disables promiscuous mode on a network
// interface using the SIOCGIFFLAGS / SIOCSIFFLAGS ioctl pair.
// This approach works for both SOCK_RAW and SOCK_DGRAM AF_PACKET sockets,
// unlike PACKET_ADD_MEMBERSHIP which requires SOCK_RAW.
func setInterfacePromisc(ifname string, enable bool) error {
	// We need any socket to issue the ioctl; a temporary INET/DGRAM is cheap.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket for ioctl: %w", err)
	}
	defer unix.Close(fd)

	var req ifreqFlags
	copy(req.Name[:], ifname)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS %s: %w", ifname, errno)
	}

	if enable {
		req.Flags |= int16(unix.IFF_PROMISC)
	} else {
		req.Flags &^= int16(unix.IFF_PROMISC)
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS %s: %w", ifname, errno)
	}
	return nil
}

// afpacketHandle wraps the afpacket.TPacket for packet capture
type afpacketHandle struct {
	TPacket       *afpacket.TPacket
	linkType      layers.LinkType
	promiscIfaces []string // interfaces put into promisc by us; restored in Close
}

// newAfpacketHandle creates a new AF_PACKET handle
func newAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int,
	timeout time.Duration, vlan bool, promisc bool, promiscIfaces []string) (*afpacketHandle, error) {

	h := &afpacketHandle{
		linkType: detectLinkType(device),
	}
	var err error

	if device == "any" {
		// Use SOCK_RAW for the "any" pseudo-interface: the kernel delivers raw
		// frames from each interface in their native framing. SOCK_DGRAM +
		// TPACKET_V3 does NOT prepend SLL headers in the ring buffer, making
		// the LinkTypeLinuxSLL decoder root useless. With SOCK_RAW the majority
		// of physical interfaces (Ethernet, WiFi) are handled correctly by the
		// Ethernet-rooted parser. Tunnel/raw-IP interfaces require explicit
		// capture (-i tunl0) where detectLinkType returns LinkTypeRaw.
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptPollTimeout(10*time.Second),
			afpacket.OptBlockTimeout(timeout),
			afpacket.OptAddVLANHeader(vlan),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptPollTimeout(10*time.Second),
			afpacket.OptBlockTimeout(timeout),
			afpacket.OptAddVLANHeader(vlan),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	if err != nil {
		return nil, err
	}

	if promisc {
		h.applyPromisc(device, promiscIfaces)
	}

	return h, nil
}

// applyPromisc sets promiscuous mode on the target interfaces.
// For a specific device it sets promisc on that device alone.
// For the "any" pseudo-interface it uses promiscIfaces: when the slice is
// non-empty only those interfaces are touched; when it is empty no
// interfaces are changed (the caller must configure promisc_interfaces
// explicitly to avoid touching unintended virtual/container interfaces).
func (h *afpacketHandle) applyPromisc(device string, promiscIfaces []string) {
	var targets []string
	if device == "any" {
		if len(promiscIfaces) == 0 {
			log.Warn().Msg("promisc=true with device=any but promisc_interfaces is empty — " +
				"set promisc_interfaces in config to enable promiscuous mode on specific interfaces")
			return
		}
		targets = promiscIfaces
	} else {
		targets = []string{device}
	}

	for _, name := range targets {
		if err := setInterfacePromisc(name, true); err != nil {
			log.Warn().Err(err).Str("interface", name).Msg("Failed to set promiscuous mode")
			continue
		}
		log.Debug().Str("interface", name).Msg("Promiscuous mode enabled")
		h.promiscIfaces = append(h.promiscIfaces, name)
	}
}

// ReadPacketData reads a packet from the handle
func (h *afpacketHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ReadPacketData()
}

// ZeroCopyReadPacketData reads a packet without copying
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetFanout sets the fanout mode for load balancing across multiple workers
func (h *afpacketHandle) SetFanout(id uint16) error {
	return h.TPacket.SetFanout(afpacket.FanoutHashWithDefrag, id)
}

// SetBPFFilter sets a BPF filter on the handle
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) error {
	// Use pcap BPF compiler to get raw BPF instruction
	pcapBPF, err := pcap.CompileBPFFilter(h.LinkType(), snaplen, filter)
	if err != nil {
		return err
	}
	rawBPF := make([]bpf.RawInstruction, len(pcapBPF))
	for i, ri := range pcapBPF {
		rawBPF[i] = bpf.RawInstruction{Op: ri.Code, Jt: ri.Jt, Jf: ri.Jf, K: ri.K}
	}
	return h.TPacket.SetBPF(rawBPF)
}

// LinkType returns the actual link type of the captured interface.
func (h *afpacketHandle) LinkType() layers.LinkType {
	return h.linkType
}

// Close closes the handle
func (h *afpacketHandle) Close() {
	for _, name := range h.promiscIfaces {
		if err := setInterfacePromisc(name, false); err != nil {
			log.Warn().Err(err).Str("interface", name).Msg("Failed to restore promiscuous mode")
		} else {
			log.Debug().Str("interface", name).Msg("Promiscuous mode restored")
		}
	}
	h.TPacket.Close()
}

// Stats returns packet and drop statistics
func (h *afpacketHandle) Stats() (uint, uint, error) {
	_, v3, err := h.TPacket.SocketStats()
	return v3.Packets(), v3.Drops(), err
}

// IsErrTimeout checks if the error is a timeout error
func (h *afpacketHandle) IsErrTimeout(err error) bool {
	return err == afpacket.ErrTimeout
}

// afpacketSupported returns true on Linux
func afpacketSupported() bool {
	return true
}
