package ownlayers

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HPERM is a custom protocol for HP ERM (HP Encapsulated Remote Mirroring)
// Typically seen on UDP port 7932
type HPERM struct {
	layers.BaseLayer
	Version uint8
}

// LayerTypeHPERM is the layer type for HPERM
var LayerTypeHPERM = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		Name:    "HPERM",
		Decoder: gopacket.DecodeFunc(decodeHPERM),
	},
)

// LayerType returns the layer type for HPERM
func (h *HPERM) LayerType() gopacket.LayerType {
	return LayerTypeHPERM
}

// DecodeFromBytes decodes HPERM header from bytes
func (h *HPERM) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 2 {
		return fmt.Errorf("HPERM packet too short")
	}

	// Simple header: just version byte followed by Ethernet frame
	h.Version = data[0]

	h.BaseLayer = layers.BaseLayer{
		Contents: data[:2],
		Payload:  data[2:],
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (h *HPERM) CanDecode() gopacket.LayerClass {
	return LayerTypeHPERM
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (h *HPERM) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func decodeHPERM(data []byte, p gopacket.PacketBuilder) error {
	hperm := &HPERM{}
	err := hperm.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(hperm)
	return p.NextDecoder(hperm.NextLayerType())
}
