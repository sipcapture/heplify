package publish

import (
	"bytes"
	"encoding/binary"

	"github.com/negbie/heplify/decoder"
)

func NewHEP(h *decoder.Packet) []byte {
	chuncks := newHEPChuncks(h)
	hepMsg := make([]byte, len(chuncks)+6)
	copy(hepMsg[6:], chuncks)
	binary.BigEndian.PutUint32(hepMsg[:4], uint32(0x48455033))
	binary.BigEndian.PutUint16(hepMsg[4:6], uint16(len(hepMsg)))
	return hepMsg
}

// MakeChunck will construct the respective HEP chunck
func makeChunck(chunckVen uint16, chunckType uint16, h *decoder.Packet) []byte {
	var chunck []byte
	switch chunckType {
	// Chunk IP protocol family (0x02=IPv4, 0x0a=IPv6)
	case 0x0001:
		chunck = make([]byte, 6+1)
		if h.Version == 4 {
			chunck[6] = 0x02
		} else if h.Version == 6 {
			chunck[6] = 0x0a
		} else {
			chunck[6] = 0x02
		}

	// Chunk IP protocol ID (0x06=TCP, 0x11=UDP)
	case 0x0002:
		chunck = make([]byte, 6+1)
		chunck[6] = h.Protocol

	// Chunk IPv4 source address
	case 0x0003:
		chunck = make([]byte, 6+len(h.SrcIP))
		copy(chunck[6:], h.SrcIP)

	// Chunk IPv4 destination address
	case 0x0004:
		chunck = make([]byte, 6+len(h.DstIP))
		copy(chunck[6:], h.DstIP)

	// Chunk IPv6 source address
	case 0x0005:
		chunck = make([]byte, 6+len(h.SrcIP))
		copy(chunck[6:], h.SrcIP)

	// Chunk IPv6 destination address
	case 0x0006:
		chunck = make([]byte, 6+len(h.DstIP))
		copy(chunck[6:], h.DstIP)

	// Chunk protocol source port
	case 0x0007:
		chunck = make([]byte, 6+2)
		binary.BigEndian.PutUint16(chunck[6:], h.SrcPort)

	// Chunk protocol destination port
	case 0x0008:
		chunck = make([]byte, 6+2)
		binary.BigEndian.PutUint16(chunck[6:], h.DstPort)

	// Chunk unix timestamp, seconds
	case 0x0009:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Tsec)

	// Chunk unix timestamp, microseconds offset
	case 0x000a:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Tmsec)

	// Chunk protocol type (DNS, LOG, RTCP, SIP)
	case 0x000b:
		chunck = make([]byte, 6+1)
		chunck[6] = h.ProtoType

	// Chunk capture agent ID
	case 0x000c:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Node)

	// Chunk keep alive timer
	// case 0x000d:

	// Chunk authenticate key (plain text / TLS connection)
	case 0x000e:
		chunck = make([]byte, len("myhep")+6)
		copy(chunck[6:], "myhep")

	// Chunk captured packet payload
	case 0x000f:
		chunck = make([]byte, len(h.Payload)+6)
		copy(chunck[6:], h.Payload)

	// Chunk captured compressed payload (gzip/inflate)
	// case 0x0010:

	// Chunk internal correlation id
	case 0x0011:
		chunck = make([]byte, len(h.CorrelationID)+6)
		copy(chunck[6:], h.CorrelationID)

	// Chunk VLAN
	case 0x0012:
		chunck = make([]byte, 6+2)
		binary.BigEndian.PutUint16(chunck[6:], h.Vlan)

	// Chunk MOS only
	case 0x0020:
		//chunck = make([]byte, 6+2)
		//binary.BigEndian.PutUint16(chunck[6:], uint16())
	}

	binary.BigEndian.PutUint16(chunck[:2], chunckVen)
	binary.BigEndian.PutUint16(chunck[2:4], chunckType)
	binary.BigEndian.PutUint16(chunck[4:6], uint16(len(chunck)))
	return chunck
}

// NewHEPChuncks will fill a buffer with all the chuncks
func newHEPChuncks(h *decoder.Packet) []byte {
	buf := new(bytes.Buffer)

	buf.Write(makeChunck(0x0000, 0x0001, h))
	buf.Write(makeChunck(0x0000, 0x0002, h))
	if h.Version == 4 {
		buf.Write(makeChunck(0x0000, 0x0003, h))
		buf.Write(makeChunck(0x0000, 0x0004, h))
	} else if h.Version == 6 {
		buf.Write(makeChunck(0x0000, 0x0005, h))
		buf.Write(makeChunck(0x0000, 0x0006, h))
	}
	buf.Write(makeChunck(0x0000, 0x0007, h))
	buf.Write(makeChunck(0x0000, 0x0008, h))
	buf.Write(makeChunck(0x0000, 0x0009, h))
	buf.Write(makeChunck(0x0000, 0x000a, h))
	buf.Write(makeChunck(0x0000, 0x000b, h))
	buf.Write(makeChunck(0x0000, 0x000c, h))
	buf.Write(makeChunck(0x0000, 0x000e, h))
	buf.Write(makeChunck(0x0000, 0x000f, h))
	if h.CorrelationID != nil {
		buf.Write(makeChunck(0x0000, 0x0011, h))
	}
	return buf.Bytes()
}
