package ownlayers

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type HPERM struct {
	layers.BaseLayer
	Unk1  [8]int8
	Unk2  bool // 1 byte - need to be 0
	secnd bool
	third bool
	Unk3  int16
}

// LayerType returns LayerTypeHPERM
func (v *HPERM) LayerType() gopacket.LayerType { return layers.LayerTypeHPERM }

func (v *HPERM) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		return fmt.Errorf("malformed HPERM packet")
	}

	flag := 0

	// check the first 8 byte - for HPERM must be all 0s
	var buffUnk1 [8]byte
	copy(buffUnk1[:], data[:9])
	for _, v := range buffUnk1 {
		if v != 0 {
			flag = 1
			break
		}
	}

	// check the 9th byte - must be 0

	// check the 12th byte - could be 0x00 or 0x80

	if flag == 1 {
		return fmt.Errorf("malformed HPERM packet")
	} else {
		fmt.Println("HPERM parsed correctly")
	}

	v.Payload = data[12:]

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (v *HPERM) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeHPERM
	// TODO implement HPERM layer here or send a PR to gopacket/layers
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (v *HPERM) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}
