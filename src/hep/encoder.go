package hep

import (
	"encoding/binary"
	"net"
)

// HEP chunk type IDs
const (
	ChunkVersion   = 0x0001
	ChunkProtocol  = 0x0002
	ChunkIP4SrcIP  = 0x0003
	ChunkIP4DstIP  = 0x0004
	ChunkIP6SrcIP  = 0x0005
	ChunkIP6DstIP  = 0x0006
	ChunkSrcPort   = 0x0007
	ChunkDstPort   = 0x0008
	ChunkTsec      = 0x0009
	ChunkTmsec     = 0x000a
	ChunkProtoType = 0x000b
	ChunkNodeID    = 0x000c
	ChunkNodePW    = 0x000e
	ChunkPayload   = 0x000f
	ChunkCID       = 0x0011
	ChunkVlan      = 0x0012
	ChunkNodeName  = 0x0013
	ChunkTCPFlag   = 0x0017
	ChunkIPTos     = 0x0018
	ChunkMOS       = 0x0020
)

// Msg holds all fields for a HEP3 packet
type Msg struct {
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
	NodePW    string
	Payload   []byte
	CID       []byte
	Vlan      uint16
	NodeName  string
	TCPFlag   uint8
	IPTos     uint8
	MOS       uint16
}

// Encode serialises a Msg into a HEP3 binary packet.
func Encode(m *Msg) []byte {
	size := m.size()
	buf := make([]byte, size)
	n := 0

	// Magic + length placeholder
	copy(buf[n:], []byte{0x48, 0x45, 0x50, 0x33})
	n += 4
	binary.BigEndian.PutUint16(buf[n:], uint16(size))
	n += 2

	putU8chunk := func(chunkID uint16, v byte) {
		binary.BigEndian.PutUint16(buf[n:], 0x0000)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], chunkID)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], 7) // 6 header + 1 byte
		n += 2
		buf[n] = v
		n++
	}
	putU16chunk := func(chunkID uint16, v uint16) {
		binary.BigEndian.PutUint16(buf[n:], 0x0000)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], chunkID)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], 8) // 6 + 2
		n += 2
		binary.BigEndian.PutUint16(buf[n:], v)
		n += 2
	}
	putU32chunk := func(chunkID uint16, v uint32) {
		binary.BigEndian.PutUint16(buf[n:], 0x0000)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], chunkID)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], 10) // 6 + 4
		n += 2
		binary.BigEndian.PutUint32(buf[n:], v)
		n += 4
	}
	putBytesChunk := func(chunkID uint16, data []byte) {
		binary.BigEndian.PutUint16(buf[n:], 0x0000)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], chunkID)
		n += 2
		binary.BigEndian.PutUint16(buf[n:], uint16(6+len(data)))
		n += 2
		copy(buf[n:], data)
		n += len(data)
	}

	putU8chunk(ChunkVersion, m.Version)
	putU8chunk(ChunkProtocol, m.Protocol)

	if m.Version == 0x02 {
		if ip4 := m.SrcIP.To4(); ip4 != nil {
			putBytesChunk(ChunkIP4SrcIP, ip4)
		}
		if ip4 := m.DstIP.To4(); ip4 != nil {
			putBytesChunk(ChunkIP4DstIP, ip4)
		}
	} else {
		if ip6 := m.SrcIP.To16(); ip6 != nil {
			putBytesChunk(ChunkIP6SrcIP, ip6)
		}
		if ip6 := m.DstIP.To16(); ip6 != nil {
			putBytesChunk(ChunkIP6DstIP, ip6)
		}
	}

	putU16chunk(ChunkSrcPort, m.SrcPort)
	putU16chunk(ChunkDstPort, m.DstPort)
	putU32chunk(ChunkTsec, m.Tsec)
	putU32chunk(ChunkTmsec, m.Tmsec)
	putU8chunk(ChunkProtoType, m.ProtoType)
	putU32chunk(ChunkNodeID, m.NodeID)

	if m.NodePW != "" {
		putBytesChunk(ChunkNodePW, []byte(m.NodePW))
	}
	if len(m.CID) > 0 {
		putBytesChunk(ChunkCID, m.CID)
	}
	putU16chunk(ChunkVlan, m.Vlan)
	if m.NodeName != "" {
		putBytesChunk(ChunkNodeName, []byte(m.NodeName))
	}
	if m.TCPFlag > 0 {
		putU8chunk(ChunkTCPFlag, m.TCPFlag)
	}
	if m.IPTos > 0 {
		putU8chunk(ChunkIPTos, m.IPTos)
	}
	if m.MOS > 0 {
		putU16chunk(ChunkMOS, m.MOS)
	}
	if len(m.Payload) > 0 {
		putBytesChunk(ChunkPayload, m.Payload)
	}

	return buf[:n]
}

func (m *Msg) size() int {
	n := 6 // "HEP3" + 2-byte length
	n += 7 // Version
	n += 7 // Protocol

	if m.Version == 0x02 {
		if ip4 := m.SrcIP.To4(); ip4 != nil {
			n += 6 + 4
		}
		if ip4 := m.DstIP.To4(); ip4 != nil {
			n += 6 + 4
		}
	} else {
		if ip6 := m.SrcIP.To16(); ip6 != nil {
			n += 6 + 16
		}
		if ip6 := m.DstIP.To16(); ip6 != nil {
			n += 6 + 16
		}
	}

	n += 8  // SrcPort
	n += 8  // DstPort
	n += 10 // Tsec
	n += 10 // Tmsec
	n += 7  // ProtoType
	n += 10 // NodeID

	if m.NodePW != "" {
		n += 6 + len(m.NodePW)
	}
	if len(m.CID) > 0 {
		n += 6 + len(m.CID)
	}
	n += 8 // Vlan
	if m.NodeName != "" {
		n += 6 + len(m.NodeName)
	}
	if m.TCPFlag > 0 {
		n += 7
	}
	if m.IPTos > 0 {
		n += 7
	}
	if m.MOS > 0 {
		n += 8
	}
	if len(m.Payload) > 0 {
		n += 6 + len(m.Payload)
	}
	return n
}
