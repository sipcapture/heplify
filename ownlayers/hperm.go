package ownlayers

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Register the layer type so we can use it
// Use negative or 2000+ for custom layers.
// It must be unique
var HPERMLayerType = gopacket.RegisterLayerType(
	2112,
	gopacket.LayerTypeMetadata{
		Name:    "HPERMLayerType",
		Decoder: gopacket.DecodeFunc(decodeHPERMLayer),
	},
)

type HPERM struct {
	Unk1  []byte
	Unk2  byte
	Unk3  byte
	payld []byte
}

// We want it to return our custom layer type
func (hp *HPERM) LayerType() gopacket.LayerType {
	return HPERMLayerType
}

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (hp *HPERM) LayerContents() []byte {
	return []byte{hp.Unk1[0], hp.Unk2, hp.Unk3}
}

// LayerPayload returns the layer built
// on top of our layer or raw payload
func (hp *HPERM) LayerPayload() []byte {
	return hp.payld
}

func decodeHPERMLayer(data []byte, p gopacket.PacketBuilder) error {

	if len(data) < 12 {
		return fmt.Errorf("malformed HPERM packet")
	}

	var flag = 0

	// check the first 8 byte - for HPERM must be all 0x00s
	//var buffUnk1 [8]byte
	//copy(buffUnk1[:], data[:9])
	for _, v := range data[:9] {
		if v != 0x00 {
			flag = 1
			break
		}
	}
	// check the 9th byte - must be 0x00
	if data[8] != 0x00 {
		flag = 1
	}
	// check the 12th byte - could be 0x00 or 0x80
	if data[11] != 0x00 && data[11] != 0x80 {
		flag = 1
	}

	if flag == 1 {
		return fmt.Errorf("malformed HPERM packet")
	} else {
		//fmt.Println("HPERM parsed correctly")
	}

	p.AddLayer(&HPERM{
		Unk1:  data[:8],
		Unk2:  data[8],
		Unk3:  data[11],
		payld: data[12:],
	})

	// The rest of the packet is the real pkt, so we decode from Ethernet again
	return p.NextDecoder(layers.LayerTypeEthernet)
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
/*func (hp *HPERM) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeHPERM
}*/

// NextLayerType returns the layer type contained by this DecodingLayer.
/*func (hp *HPERM) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}*/
