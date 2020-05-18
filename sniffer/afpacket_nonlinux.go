// +build !linux

package sniffer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type afpacketHandle struct {
}

func newAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int,
	timeout time.Duration, vlan bool) (*afpacketHandle, error) {
	return nil, fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return data, ci, fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return data, ci, fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) SetFanout(id uint16) error {
	return fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) error {
	return fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (h *afpacketHandle) Close() {
}

func (h *afpacketHandle) Stats() (uint, uint, error) {
	return 0, 0, fmt.Errorf("af_packet MMAP sniffing is only available on Linux")
}

func (h *afpacketHandle) IsErrTimeout(err error) bool {
	return false
}
