package protos

import (
	"net"

	"github.com/google/gopacket/layers"
)

type IPv6 struct {
	Version      uint8                `json:"version"`
	TrafficClass uint8                `json:"tc"`
	FlowLabel    uint32               `json:"flow"`
	Length       uint16               `json:"len"`
	NextHeader   layers.IPProtocol    `json:"proto"`
	HopLimit     uint8                `json:"hoplimit"`
	SrcIP        net.IP               `json:"srcip"`
	DstIP        net.IP               `json:"dstip"`
	HopByHop     *layers.IPv6HopByHop `json:"-"`
}

func NewIP6(ip6 *layers.IPv6) *IPv6 {
	i := &IPv6{}
	i.Version = ip6.Version
	i.TrafficClass = ip6.TrafficClass
	i.FlowLabel = ip6.FlowLabel
	i.Length = ip6.Length
	i.NextHeader = ip6.NextHeader
	i.HopLimit = ip6.HopLimit
	i.SrcIP = ip6.SrcIP
	i.DstIP = ip6.DstIP
	i.HopByHop = ip6.HopByHop
	return i
}
