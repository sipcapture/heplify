//go:build linux

package sniffer

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// afpacketHandle wraps the afpacket.TPacket for packet capture
type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

// newAfpacketHandle creates a new AF_PACKET handle
func newAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int,
	timeout time.Duration, vlan bool) (*afpacketHandle, error) {

	h := &afpacketHandle{}
	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptPollTimeout(timeout),
			afpacket.OptAddVLANHeader(vlan),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptPollTimeout(timeout),
			afpacket.OptAddVLANHeader(vlan),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return h, err
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

// LinkType returns the link type (always Ethernet for AF_PACKET)
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close closes the handle
func (h *afpacketHandle) Close() {
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
