package protos

import (
	"github.com/google/gopacket"
	"github.com/sipcapture/heplify/ownlayers"
	//"github.com/negbie/sippar"
	//"github.com/negbie/siprocket"
)

type SIP struct {
	//sipMsg        *sipparser.SipMsg
	//SipMsg        siprocket.SipMsg
	SipHeader map[string][]string
}

func NewSIP(raw []byte) []byte {
	sipl := gopacket.NewPacket(raw, ownlayers.LayerTypeSIP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	sip, ok := sipl.Layers()[0].(*ownlayers.SIP)
	if !ok {
		return nil
	}
	return sip.Contents
}
