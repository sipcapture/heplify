package decoder

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// DecodeHEP returns a parsed HEP message
func DecodeHEP(packet []byte) (*HEP, error) {
	hep := &HEP{}
	err := hep.parseHEP(packet)
	if err != nil {
		return nil, err
	}
	return hep, nil
}

func (h *HEP) parseHEP(packet []byte) error {
	length := binary.BigEndian.Uint16(packet[4:6])
	if int(length) != len(packet) {
		return fmt.Errorf("HEP packet length is %d but should be %d", len(packet), length)
	}
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := packet[currentByte:]
		if len(hepChunk) < 6 {
			return fmt.Errorf("HEP chunk must be >= 6 byte long but is %d", len(hepChunk))
		}
		//chunkVendorId := binary.BigEndian.Uint16(hepChunk[:2])
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])
		if len(hepChunk) < int(chunkLength) || int(chunkLength) < 6 {
			return fmt.Errorf("HEP chunk with %d byte < chunkLength %d or chunkLength < 6", len(hepChunk), chunkLength)
		}
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case Version, Protocol, ProtoType:
			if len(chunkBody) != 1 {
				return fmt.Errorf("HEP chunkType %d should be 1 byte long but is %d", chunkType, len(chunkBody))
			}
		case SrcPort, DstPort, Vlan:
			if len(chunkBody) != 2 {
				return fmt.Errorf("HEP chunkType %d should be 2 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP4SrcIP, IP4DstIP, Tsec, Tmsec, NodeID:
			if len(chunkBody) != 4 {
				return fmt.Errorf("HEP chunkType %d should be 4 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP6SrcIP, IP6DstIP:
			if len(chunkBody) != 16 {
				return fmt.Errorf("HEP chunkType %d should be 16 byte long but is %d", chunkType, len(chunkBody))
			}
		}

		switch chunkType {
		case Version:
			h.Version = uint32(chunkBody[0])
		case Protocol:
			h.Protocol = uint32(chunkBody[0])
		case IP4SrcIP:
			h.SrcIP = net.IP(chunkBody).To4().String()
		case IP4DstIP:
			h.DstIP = net.IP(chunkBody).To4().String()
		case IP6SrcIP:
			h.SrcIP = net.IP(chunkBody).To16().String()
		case IP6DstIP:
			h.DstIP = net.IP(chunkBody).To16().String()
		case SrcPort:
			h.SrcPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case DstPort:
			h.DstPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case Tsec:
			h.Tsec = binary.BigEndian.Uint32(chunkBody)
		case Tmsec:
			h.Tmsec = binary.BigEndian.Uint32(chunkBody)
		case ProtoType:
			h.ProtoType = uint32(chunkBody[0])
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
		case NodeID:
			h.NodeID = binary.BigEndian.Uint32(chunkBody)
		case NodePW:
			h.NodePW = string(chunkBody)
		case Payload:
			h.Payload = string(chunkBody)
		case CID:
			h.CID = string(chunkBody)
		case Vlan:
			h.Vlan = uint32(binary.BigEndian.Uint16(chunkBody))
		case NodeName:
			h.NodeName = string(chunkBody)
		default:
		}
		currentByte += chunkLength
	}
	return nil
}
