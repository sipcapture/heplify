package publish

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	strings "strings"
	"unsafe"

	proto "github.com/gogo/protobuf/proto"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

var (
	hepVer   = []byte{0x48, 0x45, 0x50, 0x33} // "HEP3"
	hepLen   = []byte{0x00, 0x00}
	hepLen7  = []byte{0x00, 0x07}
	hepLen8  = []byte{0x00, 0x08}
	hepLen10 = []byte{0x00, 0x0a}
	chunck16 = []byte{0x00, 0x00}
	chunck32 = []byte{0x00, 0x00, 0x00, 0x00}
)

// HEP chuncks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
)

// HepMsg represents a parsed HEP packet
type HepMsg struct {
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	NodeID    uint32
	NodePW    []byte
	Payload   []byte
	CID       []byte
	Vlan      uint16
}

// EncodeHEP creates the HEP Packet which
// will be send to wire
func EncodeHEP(h *decoder.Packet) []byte {
	var hepMsg []byte
	var err error
	if config.Cfg.Protobuf {
		hep := &HEP{
			Version:   uint32(h.Version),
			Protocol:  uint32(h.Protocol),
			SrcIP:     h.SrcIP.String(),
			DstIP:     h.DstIP.String(),
			SrcPort:   uint32(h.SrcPort),
			DstPort:   uint32(h.DstPort),
			Tsec:      h.Tsec,
			Tmsec:     h.Tmsec,
			ProtoType: uint32(h.ProtoType),
			NodeID:    h.NodeID,
			NodePW:    unsafeBytesToStr(h.NodePW),
			Payload:   unsafeBytesToStr(h.Payload),
			CID:       unsafeBytesToStr(h.CID),
			Vlan:      uint32(h.Vlan),
		}
		hepMsg, err = proto.Marshal(hep)
		if err != nil {
			logp.Warn("%v", err)
		}
	} else {
		hepMsg = makeHEPChuncks(h)
		binary.BigEndian.PutUint16(hepMsg[4:6], uint16(len(hepMsg)))
	}
	return hepMsg
}

// makeHEPChuncks will construct the respective HEP chunck
func makeHEPChuncks(h *decoder.Packet) []byte {
	w := new(bytes.Buffer)
	w.Write(hepVer)
	// hepMsg length placeholder. Will be written later
	w.Write(hepLen)

	// Chunk IP protocol family (0x02=IPv4, 0x0a=IPv6)
	w.Write([]byte{0x00, 0x00, 0x00, 0x01})
	w.Write(hepLen7)
	w.WriteByte(h.Version)

	// Chunk IP protocol ID (0x06=TCP, 0x11=UDP)
	w.Write([]byte{0x00, 0x00, 0x00, 0x02})
	w.Write(hepLen7)
	w.WriteByte(h.Protocol)

	if h.Version == 0x02 {
		// Chunk IPv4 source address
		w.Write([]byte{0x00, 0x00, 0x00, 0x03})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.SrcIP)))
		w.Write(hepLen)
		w.Write(h.SrcIP)

		// Chunk IPv4 destination address
		w.Write([]byte{0x00, 0x00, 0x00, 0x04})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.DstIP)))
		w.Write(hepLen)
		w.Write(h.DstIP)
	} else if h.Version == 0x0a {
		// Chunk IPv6 source address
		w.Write([]byte{0x00, 0x00, 0x00, 0x05})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.SrcIP)))
		w.Write(hepLen)
		w.Write(h.SrcIP)

		// Chunk IPv6 destination address
		w.Write([]byte{0x00, 0x00, 0x00, 0x06})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.DstIP)))
		w.Write(hepLen)
		w.Write(h.DstIP)
	}

	// Chunk protocol source port
	w.Write([]byte{0x00, 0x00, 0x00, 0x07})
	w.Write(hepLen8)
	binary.BigEndian.PutUint16(chunck16, h.SrcPort)
	w.Write(chunck16)

	// Chunk protocol destination port
	w.Write([]byte{0x00, 0x00, 0x00, 0x08})
	w.Write(hepLen8)
	binary.BigEndian.PutUint16(chunck16, h.DstPort)
	w.Write(chunck16)

	// Chunk unix timestamp, seconds
	w.Write([]byte{0x00, 0x00, 0x00, 0x09})
	w.Write(hepLen10)
	binary.BigEndian.PutUint32(chunck32, h.Tsec)
	w.Write(chunck32)

	// Chunk unix timestamp, microseconds offset
	w.Write([]byte{0x00, 0x00, 0x00, 0x0a})
	w.Write(hepLen10)
	binary.BigEndian.PutUint32(chunck32, h.Tmsec)
	w.Write(chunck32)

	// Chunk protocol type (DNS, LOG, RTCP, SIP)
	w.Write([]byte{0x00, 0x00, 0x00, 0x0b})
	w.Write(hepLen7)
	w.WriteByte(h.ProtoType)

	// Chunk capture agent ID
	w.Write([]byte{0x00, 0x00, 0x00, 0x0c})
	w.Write(hepLen10)
	binary.BigEndian.PutUint32(chunck32, h.NodeID)
	w.Write(chunck32)

	// Chunk keep alive timer
	//w.Write([]byte{0x00, 0x00, 0x00, 0x0d})

	// Chunk authenticate key (plain text / TLS connection)
	w.Write([]byte{0x00, 0x00, 0x00, 0x0e})
	binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.NodePW)))
	w.Write(hepLen)
	w.Write(h.NodePW)

	// Chunk captured packet payload
	w.Write([]byte{0x00, 0x00, 0x00, 0x0f})
	binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.Payload)))
	w.Write(hepLen)
	w.Write(h.Payload)

	// Chunk captured compressed payload (gzip/inflate)
	//w.Write([]byte{0x00,0x00, 0x00,0x10})

	if h.CID != nil {
		// Chunk internal correlation id
		w.Write([]byte{0x00, 0x00, 0x00, 0x11})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.CID)))
		w.Write(hepLen)
		w.Write(h.CID)
	}
	/*
		// Chunk VLAN
		w.Write([]byte{0x00, 0x00, 0x00, 0x12})
		w.Write(hepLen8)
		binary.BigEndian.PutUint16(chunck16, h.Vlan)
		w.Write(chunck16)

		// Chunk MOS only
		w.Write([]byte{0x00, 0x00, 0x00, 0x20})
		w.Write(hepLen8)
		binary.BigEndian.PutUint16(chunck16, h.MOS)
		w.Write(chunck16)
	*/
	return w.Bytes()
}

// DecodeHEP returns a parsed HEP message
func DecodeHEP(packet []byte) (*HepMsg, error) {
	newHepMsg := &HepMsg{}
	err := newHepMsg.parse(packet)
	if err != nil {
		return nil, err
	}
	return newHepMsg, nil
}

func (h *HepMsg) parse(packet []byte) error {
	if packet[0] == 0x48 && packet[3] == 0x33 {
		return h.parseHep(packet)
	}
	return errors.New("Not a valid HEP3 packet")
}

func (h *HepMsg) parseHep(packet []byte) error {
	length := binary.BigEndian.Uint16(packet[4:6])
	if int(length) != len(packet) {
		return fmt.Errorf("HEP packet length is %d but should be %d", len(packet), length)
	}
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := packet[currentByte:]
		//chunkVendorId := binary.BigEndian.Uint16(hepChunk[:2])
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])
		if len(hepChunk) < int(chunkLength) {
			return fmt.Errorf("HEP chunk overflow %d > %d", chunkLength, len(hepChunk))
		}
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case Version:
			h.Version = chunkBody[0]
		case Protocol:
			h.Protocol = chunkBody[0]
		case IP4SrcIP:
			h.SrcIP = chunkBody
		case IP4DstIP:
			h.DstIP = chunkBody
		case IP6SrcIP:
			h.SrcIP = chunkBody
		case IP6DstIP:
			h.DstIP = chunkBody
		case SrcPort:
			h.SrcPort = binary.BigEndian.Uint16(chunkBody)
		case DstPort:
			h.DstPort = binary.BigEndian.Uint16(chunkBody)
		case Tsec:
			h.Tsec = binary.BigEndian.Uint32(chunkBody)
		case Tmsec:
			h.Tmsec = binary.BigEndian.Uint32(chunkBody)
		case ProtoType:
			h.ProtoType = chunkBody[0]
		case NodeID:
			h.NodeID = binary.BigEndian.Uint32(chunkBody)
		case NodePW:
			h.NodePW = chunkBody
		case Payload:
			h.Payload = chunkBody
		case CID:
			h.CID = chunkBody
		case Vlan:
			h.Vlan = binary.BigEndian.Uint16(chunkBody)
		default:
		}
		currentByte += chunkLength
	}
	return nil
}
func (h *HepMsg) String() string {
	if h == nil {
		return "nil"
	}
	s := strings.Join([]string{`&HEP{`,
		`Version:` + fmt.Sprintf("%v", h.Version) + `,`,
		`Protocol:` + fmt.Sprintf("%v", h.Protocol) + `,`,
		`SrcIP:` + fmt.Sprintf("%v", h.SrcIP) + `,`,
		`DstIP:` + fmt.Sprintf("%v", h.DstIP) + `,`,
		`SrcPort:` + fmt.Sprintf("%v", h.SrcPort) + `,`,
		`DstPort:` + fmt.Sprintf("%v", h.DstPort) + `,`,
		`Tsec:` + fmt.Sprintf("%v", h.Tsec) + `,`,
		`Tmsec:` + fmt.Sprintf("%v", h.Tmsec) + `,`,
		`ProtoType:` + fmt.Sprintf("%v", h.ProtoType) + `,`,
		`NodeID:` + fmt.Sprintf("%v", h.NodeID) + `,`,
		`NodePW:` + fmt.Sprintf("%s", h.NodePW) + `,`,
		`Payload:` + fmt.Sprintf("%s", strconv.Quote(string(h.Payload))) + `,`,
		`CID:` + fmt.Sprintf("%s", h.CID) + `,`,
		`Vlan:` + fmt.Sprintf("%v", h.Vlan) + `,`,
		`}`,
	}, "")
	return s
}

func unsafeBytesToStr(z []byte) string {
	return *(*string)(unsafe.Pointer(&z))
}
