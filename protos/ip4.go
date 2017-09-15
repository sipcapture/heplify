package protos

import (
	"net"

	"github.com/google/gopacket/layers"
)

type IPv4 struct {
	Version    uint8               `json:"version"`
	IHL        uint8               `json:"ihl"`
	TOS        uint8               `json:"tos"`
	Length     uint16              `json:"len"`
	Id         uint16              `json:"id"`
	Flags      layers.IPv4Flag     `json:"flags"`
	FragOffset uint16              `json:"offset"`
	TTL        uint8               `json:"ttl"`
	Protocol   layers.IPProtocol   `json:"proto"`
	Checksum   uint16              `json:"checksum"`
	SrcIP      net.IP              `json:"srcip"`
	DstIP      net.IP              `json:"dstip"`
	Options    []layers.IPv4Option `json:"-"`
	Padding    []byte              `json:"padding,omitempty"`
}

func NewIP4(ip *layers.IPv4) *IPv4 {
	i := &IPv4{}
	i.Version = ip.Version
	i.IHL = ip.IHL
	i.TOS = ip.TOS
	i.Length = ip.Length
	i.Id = ip.Id
	i.Flags = ip.Flags
	i.FragOffset = ip.FragOffset
	i.TTL = ip.TTL
	i.Protocol = ip.Protocol
	i.Checksum = ip.Checksum
	i.SrcIP = ip.SrcIP
	i.DstIP = ip.DstIP
	i.Options = ip.Options
	i.Padding = ip.Padding
	return i
}
