package protos

import (
	"github.com/google/gopacket/layers"
)

type TCP struct {
	SrcPort layers.TCPPort `json:"srcport"`
	DstPort layers.TCPPort `json:"dstport"`
	Payload []byte         `json:"payload,omitempty"`
}

func NewTCP(tcp *layers.TCP) (t *TCP) {
	t = &TCP{}
	t.SrcPort = tcp.SrcPort
	t.DstPort = tcp.DstPort
	t.Payload = tcp.Payload
	return t
}
