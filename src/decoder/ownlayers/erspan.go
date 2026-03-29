package ownlayers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ERSPANVersion represents the ERSPAN version
type ERSPANVersion uint8

const (
	ERSPANVersion1 ERSPANVersion = 1
	ERSPANVersion2 ERSPANVersion = 2
)

// ERSPAN represents an ERSPAN (Encapsulated Remote SPAN) header
// ERSPAN Type II (Version 1) and Type III (Version 2) are supported
type ERSPAN struct {
	layers.BaseLayer
	Version   ERSPANVersion
	VLan      uint16
	CoS       uint8  // Class of Service (3 bits)
	Truncated bool   // Truncation bit
	SpanID    uint16 // 10 bits
	// Type II only fields
	Index uint32 // 20 bits
	// Type III only fields
	Timestamp  uint32
	SGT        uint16 // Security Group Tag
	PlatformID uint8  // 6 bits
	FrameType  uint8  // 5 bits
	Direction  uint8  // 1 bit
	GranTime   uint8  // 2 bits
	HardwareID uint8  // 6 bits
}

// LayerTypeERSPAN is the layer type for ERSPAN
var LayerTypeERSPAN = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		Name:    "ERSPAN",
		Decoder: gopacket.DecodeFunc(decodeERSPAN),
	},
)

// LayerType returns the layer type for ERSPAN
func (e *ERSPAN) LayerType() gopacket.LayerType {
	return LayerTypeERSPAN
}

// DecodeFromBytes decodes ERSPAN header from bytes
func (e *ERSPAN) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		return fmt.Errorf("ERSPAN packet too short")
	}

	// First 4 bits are version
	e.Version = ERSPANVersion(data[0] >> 4)

	switch e.Version {
	case ERSPANVersion1:
		return e.decodeVersion1(data, df)
	case ERSPANVersion2:
		return e.decodeVersion2(data, df)
	default:
		return fmt.Errorf("unsupported ERSPAN version: %d", e.Version)
	}
}

func (e *ERSPAN) decodeVersion1(data []byte, _ gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		return fmt.Errorf("ERSPAN Type II packet too short")
	}

	// Bytes 0-1: Version (4 bits) + VLAN (12 bits)
	e.VLan = binary.BigEndian.Uint16(data[0:2]) & 0x0FFF

	// Bytes 2-3: CoS (3 bits) + Encap (2 bits) + T (1 bit) + Session ID (10 bits)
	word2 := binary.BigEndian.Uint16(data[2:4])
	e.CoS = uint8((word2 >> 13) & 0x07)
	e.Truncated = (word2>>10)&0x01 == 1
	e.SpanID = word2 & 0x03FF

	// Bytes 4-7: Reserved (12 bits) + Index (20 bits)
	word3 := binary.BigEndian.Uint32(data[4:8])
	e.Index = word3 & 0x000FFFFF

	e.BaseLayer = layers.BaseLayer{
		Contents: data[:8],
		Payload:  data[8:],
	}

	return nil
}

func (e *ERSPAN) decodeVersion2(data []byte, _ gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		return fmt.Errorf("ERSPAN Type III packet too short")
	}

	// Bytes 0-1: Version (4 bits) + VLAN (12 bits)
	e.VLan = binary.BigEndian.Uint16(data[0:2]) & 0x0FFF

	// Bytes 2-3: CoS (3 bits) + BSO (2 bits) + T (1 bit) + Session ID (10 bits)
	word2 := binary.BigEndian.Uint16(data[2:4])
	e.CoS = uint8((word2 >> 13) & 0x07)
	e.Truncated = (word2>>10)&0x01 == 1
	e.SpanID = word2 & 0x03FF

	// Bytes 4-7: Timestamp
	e.Timestamp = binary.BigEndian.Uint32(data[4:8])

	// Bytes 8-9: SGT (Security Group Tag)
	e.SGT = binary.BigEndian.Uint16(data[8:10])

	// Bytes 10-11: P (1 bit) + FT (5 bits) + HW (6 bits) + D (1 bit) + Gra (2 bits) + O (1 bit)
	word5 := binary.BigEndian.Uint16(data[10:12])
	e.PlatformID = uint8((word5 >> 10) & 0x3F)
	e.FrameType = uint8((word5 >> 5) & 0x1F)
	e.HardwareID = uint8((word5 >> 4) & 0x3F)
	e.Direction = uint8((word5 >> 3) & 0x01)
	e.GranTime = uint8((word5 >> 1) & 0x03)

	e.BaseLayer = layers.BaseLayer{
		Contents: data[:12],
		Payload:  data[12:],
	}

	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (e *ERSPAN) CanDecode() gopacket.LayerClass {
	return LayerTypeERSPAN
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (e *ERSPAN) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func decodeERSPAN(data []byte, p gopacket.PacketBuilder) error {
	erspan := &ERSPAN{}
	err := erspan.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(erspan)
	return p.NextDecoder(erspan.NextLayerType())
}
