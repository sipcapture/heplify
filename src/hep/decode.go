package hep

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
)

// HEP chunk type IDs (vendor 0x0000).
const (
	chunkVersion   = 1
	chunkProtocol  = 2
	chunkIP4SrcIP  = 3
	chunkIP4DstIP  = 4
	chunkIP6SrcIP  = 5
	chunkIP6DstIP  = 6
	chunkSrcPort   = 7
	chunkDstPort   = 8
	chunkTsec      = 9
	chunkTmsec     = 10
	chunkProtoType = 11
	chunkNodeID    = 12
	chunkNodePW    = 14
	chunkPayload   = 15
	chunkCID       = 17
	chunkVlan      = 18
	chunkNodeName  = 19
)

// HEP holds a decoded HEP v2/v3 packet.
type HEP struct {
	Version     uint32
	Protocol    uint32
	SrcIP       string
	DstIP       string
	SrcPort     uint32
	DstPort     uint32
	Tsec        uint32
	Tmsec       uint32
	ProtoType   uint32
	NodeID      uint32
	NodePW      string
	Payload     string
	CID         string
	Vlan        uint32
	ProtoString string
	Timestamp   time.Time
	NodeName    string
}

// DecodeHEP parses a raw HEP3 packet and returns a populated HEP struct.
func DecodeHEP(packet []byte) (*HEP, error) {
	h := &HEP{}
	if err := h.parseHEP(packet); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *HEP) parseHEP(packet []byte) error {
	if len(packet) < 6 {
		return fmt.Errorf("HEP packet too short: %d bytes", len(packet))
	}
	length := binary.BigEndian.Uint16(packet[4:6])
	if int(length) != len(packet) {
		return fmt.Errorf("HEP packet length is %d but should be %d", len(packet), length)
	}
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := packet[currentByte:]
		if len(hepChunk) < 6 {
			return fmt.Errorf("HEP chunk must be >= 6 bytes but is %d", len(hepChunk))
		}
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLen := binary.BigEndian.Uint16(hepChunk[4:6])
		if len(hepChunk) < int(chunkLen) || int(chunkLen) < 6 {
			return fmt.Errorf("HEP chunk length %d invalid (available %d)", chunkLen, len(hepChunk))
		}
		body := hepChunk[6:chunkLen]

		switch chunkType {
		case chunkVersion:
			h.Version = uint32(body[0])
		case chunkProtocol:
			h.Protocol = uint32(body[0])
		case chunkIP4SrcIP:
			h.SrcIP = net.IP(body).To4().String()
		case chunkIP4DstIP:
			h.DstIP = net.IP(body).To4().String()
		case chunkIP6SrcIP:
			h.SrcIP = net.IP(body).To16().String()
		case chunkIP6DstIP:
			h.DstIP = net.IP(body).To16().String()
		case chunkSrcPort:
			h.SrcPort = uint32(binary.BigEndian.Uint16(body))
		case chunkDstPort:
			h.DstPort = uint32(binary.BigEndian.Uint16(body))
		case chunkTsec:
			h.Tsec = binary.BigEndian.Uint32(body)
		case chunkTmsec:
			h.Tmsec = binary.BigEndian.Uint32(body)
		case chunkProtoType:
			h.ProtoType = uint32(body[0])
			switch h.ProtoType {
			case 1:
				h.ProtoString = "sip"
			case 5:
				h.ProtoString = "rtcp"
			case 34:
				h.ProtoString = "rtpagent"
			case 35:
				h.ProtoString = "rtcpxr"
			case 38:
				h.ProtoString = "horaclifix"
			case 53:
				h.ProtoString = "dns"
			case 100:
				h.ProtoString = "log"
			default:
				h.ProtoString = strconv.Itoa(int(h.ProtoType))
			}
		case chunkNodeID:
			h.NodeID = binary.BigEndian.Uint32(body)
		case chunkNodePW:
			h.NodePW = string(body)
		case chunkPayload:
			h.Payload = string(body)
		case chunkCID:
			h.CID = string(body)
		case chunkVlan:
			h.Vlan = uint32(binary.BigEndian.Uint16(body))
		case chunkNodeName:
			h.NodeName = string(body)
		}
		currentByte += chunkLen
	}
	return nil
}
