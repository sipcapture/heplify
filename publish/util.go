package publish

import (
	"bytes"
	"encoding/binary"
	"sync"

	"github.com/negbie/heplify/decoder"
)

var hepVer = []byte{48, 45, 50, 33} // "HEP3"
var hepLen = []byte{0, 0}
var chunck16 = []byte{0, 0}
var chunck32 = []byte{0, 0, 0, 0}

// hepBuffer pool to reduce GC
var hepBuffer = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// GetBuffer fetches a buffer from the pool
func GetBuffer() *bytes.Buffer {
	return hepBuffer.Get().(*bytes.Buffer)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	hepBuffer.Put(buf)
}

// NewHEP creates the HEP Packet which
// will be send to wire
func NewHEP(h *decoder.Packet) []byte {
	buf := GetBuffer()
	hepMsg := makeChuncks(h, buf)
	binary.BigEndian.PutUint16(hepMsg[4:6], uint16(6+len(hepMsg)))
	PutBuffer(buf)
	return hepMsg
}

// makeChuncks will construct the respective HEP chunck
func makeChuncks(h *decoder.Packet, w *bytes.Buffer) []byte {
	w.Write(hepVer)
	w.Write(hepLen)

	// Chunk IP protocol family (0x02=IPv4, 0x0a=IPv6)
	w.Write([]byte{0, 0, 0, 1})
	binary.BigEndian.PutUint16(hepLen, 6+1)
	w.Write(hepLen)
	w.WriteByte(h.Version)

	// Chunk IP protocol ID (0x06=TCP, 0x11=UDP)
	w.Write([]byte{0, 0, 0, 2})
	binary.BigEndian.PutUint16(hepLen, 6+1)
	w.Write(hepLen)
	w.WriteByte(h.Protocol)

	if h.Version == 0x02 {
		// Chunk IPv4 source address
		w.Write([]byte{0, 0, 0, 3})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.SrcIP)))
		w.Write(hepLen)
		w.Write(h.SrcIP)

		// Chunk IPv4 destination address
		w.Write([]byte{0, 0, 0, 4})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.DstIP)))
		w.Write(hepLen)
		w.Write(h.DstIP)
	} else if h.Version == 0x0a {
		// Chunk IPv6 source address
		w.Write([]byte{0, 0, 0, 5})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.SrcIP)))
		w.Write(hepLen)
		w.Write(h.SrcIP)

		// Chunk IPv6 destination address
		w.Write([]byte{0, 0, 0, 6})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.DstIP)))
		w.Write(hepLen)
		w.Write(h.DstIP)
	}

	// Chunk protocol source port
	w.Write([]byte{0, 0, 0, 7})
	binary.BigEndian.PutUint16(hepLen, 6+2)
	w.Write(hepLen)
	binary.BigEndian.PutUint16(chunck16, h.SrcPort)
	w.Write(chunck16)

	// Chunk protocol destination port
	w.Write([]byte{0, 0, 0, 8})
	binary.BigEndian.PutUint16(hepLen, 6+2)
	w.Write(hepLen)
	binary.BigEndian.PutUint16(chunck16, h.DstPort)
	w.Write(chunck16)

	// Chunk unix timestamp, seconds
	w.Write([]byte{0, 0, 0, 9})
	binary.BigEndian.PutUint16(hepLen, 6+4)
	w.Write(hepLen)
	binary.BigEndian.PutUint32(chunck32, h.Tsec)
	w.Write(chunck32)

	// Chunk unix timestamp, microseconds offset
	w.Write([]byte{0, 0, 0, 10})
	binary.BigEndian.PutUint16(hepLen, 6+4)
	w.Write(hepLen)
	binary.BigEndian.PutUint32(chunck32, h.Tmsec)
	w.Write(chunck32)

	// Chunk protocol type (DNS, LOG, RTCP, SIP)
	w.Write([]byte{0, 0, 0, 11})
	binary.BigEndian.PutUint16(hepLen, 6+1)
	w.Write(hepLen)
	w.WriteByte(h.ProtoType)

	// Chunk capture agent ID
	w.Write([]byte{0, 0, 0, 12})
	binary.BigEndian.PutUint16(hepLen, 6+4)
	w.Write(hepLen)
	binary.BigEndian.PutUint32(chunck32, h.NodeID)
	w.Write(chunck32)

	// Chunk keep alive timer
	//w.Write([]byte{0, 0, 0, 13})

	// Chunk authenticate key (plain text / TLS connection)
	w.Write([]byte{0, 0, 0, 14})
	binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.NodePW)))
	w.Write(hepLen)
	w.Write(h.NodePW)

	// Chunk captured packet payload
	w.Write([]byte{0, 0, 0, 15})
	binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.Payload)))
	w.Write(hepLen)
	w.Write(h.Payload)

	// Chunk captured compressed payload (gzip/inflate)
	//w.Write([]byte{0, 0, 0, 16})

	if h.CorrelationID != nil {
		// Chunk internal correlation id
		w.Write([]byte{0, 0, 0, 17})
		binary.BigEndian.PutUint16(hepLen, 6+uint16(len(h.CorrelationID)))
		w.Write(hepLen)
		w.Write(h.CorrelationID)
	}

	// Chunk VLAN
	w.Write([]byte{0, 0, 0, 18})
	binary.BigEndian.PutUint16(hepLen, 6+2)
	w.Write(hepLen)
	binary.BigEndian.PutUint16(chunck16, h.Vlan)
	w.Write(chunck16)

	// Chunk MOS only
	//w.Write([]byte{0,0,0,32})
	//binary.BigEndian.PutUint16(w.Bytes(), 6+2)
	//binary.BigEndian.PutUint16(w.Bytes(), h.MOS)

	return w.Bytes()
}
