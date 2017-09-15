package protos

import (
	"github.com/google/gopacket/layers"
)

type UDP struct {
	SrcPort layers.UDPPort `json:"srcport"`
	DstPort layers.UDPPort `json:"dstport"`
	Payload []byte         `json:"payload,omitempty"`
}

func NewUDP(udp *layers.UDP) (u *UDP) {
	u = &UDP{}
	u.SrcPort = udp.SrcPort
	u.DstPort = udp.DstPort
	u.Payload = udp.Payload
	return u
}
