//go:build !linux

package sniffer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// afpacketHandle is a stub for non-Linux systems
type afpacketHandle struct{}

// newAfpacketHandle returns an error on non-Linux systems
func newAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int,
	timeout time.Duration, vlan bool, promisc bool, promiscIfaces []string) (*afpacketHandle, error) {
	return nil, fmt.Errorf("AF_PACKET is only supported on Linux")
}

// ReadPacketData is not supported on non-Linux
func (h *afpacketHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return nil, gopacket.CaptureInfo{}, fmt.Errorf("AF_PACKET not supported")
}

// ZeroCopyReadPacketData is not supported on non-Linux
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return nil, gopacket.CaptureInfo{}, fmt.Errorf("AF_PACKET not supported")
}

// SetFanout is not supported on non-Linux
func (h *afpacketHandle) SetFanout(id uint16) error {
	return fmt.Errorf("AF_PACKET not supported")
}

// SetBPFFilter is not supported on non-Linux
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) error {
	return fmt.Errorf("AF_PACKET not supported")
}

// LinkType returns Ethernet
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close is a no-op on non-Linux
func (h *afpacketHandle) Close() {}

// Stats returns zeros on non-Linux
func (h *afpacketHandle) Stats() (uint, uint, error) {
	return 0, 0, fmt.Errorf("AF_PACKET not supported")
}

// IsErrTimeout always returns false on non-Linux
func (h *afpacketHandle) IsErrTimeout(err error) bool {
	return false
}

// afpacketSupported returns false on non-Linux
func afpacketSupported() bool {
	return false
}
