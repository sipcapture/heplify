package ownlayers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VXLAN represents a VXLAN (Virtual Extensible LAN) header
type VXLAN struct {
	layers.BaseLayer
	ValidIDFlag bool   // 'I' bit per RFC 7348
	VNI         uint32 // 'VXLAN Network Identifier' 24 bits per RFC 7348
}

// LayerType returns LayerTypeVXLAN
func (v *VXLAN) LayerType() gopacket.LayerType { return layers.LayerTypeVXLAN }

// DecodeFromBytes decodes VXLAN header from bytes
func (v *VXLAN) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 || data[0] != 0x08 {
		return fmt.Errorf("malformed VXLAN packet")
	}

	// VNI is a 24bit number, Uint32 requires 32 bits
	var buf [4]byte
	copy(buf[1:], data[4:7])

	// RFC 7348 https://tools.ietf.org/html/rfc7348
	v.ValidIDFlag = data[0]&0x08 > 0        // 'I' bit per RFC7348
	v.VNI = binary.BigEndian.Uint32(buf[:]) // VXLAN Network Identifier per RFC7348

	v.BaseLayer = layers.BaseLayer{
		Contents: data[:8],
		Payload:  data[8:],
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (v *VXLAN) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeVXLAN
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (v *VXLAN) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}
