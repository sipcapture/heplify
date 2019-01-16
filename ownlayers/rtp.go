package ownlayers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

// LayerTypeRTP registers the RTP layer type 2010.
var LayerTypeRTP = gopacket.RegisterLayerType(2010, gopacket.LayerTypeMetadata{Name: "RTP", Decoder: gopacket.DecodeFunc(decodeRTP)})

// RTP represents a RTP packet.
type RTP struct {
	Version               uint8
	Padding               uint8
	Extension             uint8
	CC                    uint8
	Marker                uint8
	PayloadType           uint8
	SequenceNumber        uint16
	Timestamp             uint32
	Ssrc                  uint32
	Csrc                  []uint32
	ExtensionHeaderID     uint16
	ExtensionHeaderLength uint16
	ExtensionHeader       []byte
	Payload               []byte
	Contents              []byte
}

// String returns a string version of RTP.
func (r *RTP) String() string {
	return fmt.Sprintf(
		"Version:\t%d\nPadding:\t%d\nExtension:\t%d\nCC:\t\t%d\nMarker:\t\t%d\nPayloadType:\t%d\nSequenceNum:\t%d\nTimestamp:\t%d\nSsrc:\t\t0x%x\nPayload:\t0x%x\n",
		r.Version,
		r.Padding,
		r.Extension,
		r.CC,
		r.Marker,
		r.PayloadType,
		r.SequenceNumber,
		r.Timestamp,
		r.Ssrc,
		r.Payload,
	)
}

// Length returns the RTP Contents length.
func (r *RTP) Length() int {
	return len(r.Contents)
}

// LayerType returns the layer type of the RTP object, which is LayerTypeRTP.
func (r *RTP) LayerType() gopacket.LayerType {
	return LayerTypeRTP
}

// CanDecode returns a set of layers that RTP objects can decode, which is just LayerTypeRTP.
func (r *RTP) CanDecode() gopacket.LayerClass {
	return LayerTypeRTP
}

// NextLayerType specifies the next layer that should be decoded. VRRP does not contain any further payload, so we set to 0
func (r *RTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (r *RTP) LayerContents() []byte {
	return r.Contents
}

func (r *RTP) LayerPayload() []byte {
	return nil
}

//DecodeFromBytes decodes the given bytes into this layer.
func (r *RTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		return errors.New("the RTP header should have at least 12 octets")
	}

	r.Version = data[0] & 0xC0 >> 6
	if r.Version != 2 {
		return errors.New("the RTP version != 2")
	}

	r.Padding = data[0] & 0x20
	r.Extension = data[0] & 0x10
	r.CC = data[0] & 0x0F
	r.Marker = data[1] & 0x80
	r.PayloadType = data[1] & 0x7F
	r.SequenceNumber = binary.BigEndian.Uint16(data[2:])
	r.Timestamp = binary.BigEndian.Uint32(data[4:])
	r.Ssrc = binary.BigEndian.Uint32(data[8:])
	offset := 12

	if r.Padding > 1 || r.Extension > 1 || r.Marker > 1 {
		return errors.New("no valid RTP packet")
	}

	if r.CC > 0 {
		if len(data[offset:]) < int(r.CC*4) {
			return errors.New("not enough octets left in RTP header to get CC")
		}
		r.Csrc = make([]uint32, r.CC)
		for i := 0; i < int(r.CC); i++ {
			r.Csrc[i] = binary.BigEndian.Uint32(data[offset:])
			offset += 4
		}
	}

	if r.Extension == 1 {
		if len(data[offset:]) < 4 {
			return errors.New("not enough octets left in RTP header to get ExtensionHeaderID and ExtensionHeaderLength")
		}
		r.ExtensionHeaderID = binary.BigEndian.Uint16(data[offset:])
		offset += 2
		r.ExtensionHeaderLength = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	if r.ExtensionHeaderLength > 0 {
		if len(data[offset:]) < 4*int(r.ExtensionHeaderLength) {
			return errors.New("not enough octets left in RTP header to get the Extensions")
		}
		r.ExtensionHeader = make([]byte, 4*int(r.ExtensionHeaderLength))
		r.ExtensionHeader = data[offset : offset+4*int(r.ExtensionHeaderLength)]
		offset += 4 * int(r.ExtensionHeaderLength)
	}

	if len(data[offset:]) == 0 {
		return errors.New("no content in RTP packet")
	}

	if r.Padding == 1 {
		padLen := int(data[len(data)-1])
		if padLen <= 0 || padLen > len(data[offset:]) {
			return errors.New("invalid padding length")
		}

		r.Payload = data[offset : len(data)-padLen]
	} else {
		r.Payload = data[offset:]
	}
	return nil
}

// This function is employed in layertypes.go to register the BFD layer.
func decodeRTP(data []byte, p gopacket.PacketBuilder) error {

	r := &RTP{}
	r.Contents = data[:]
	err := r.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	// If the decoding worked, add the layer to the packet.
	p.AddLayer(r)
	return nil
}
