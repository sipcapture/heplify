package hep

import "encoding/binary"

// PayloadBytes returns the raw bytes of HEP chunk 0x000f (Payload) if present.
func PayloadBytes(packet []byte) []byte {
	if len(packet) < 6 || string(packet[0:4]) != "HEP3" {
		return nil
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if length > len(packet) {
		length = len(packet)
	}
	offset := 6
	for offset+6 <= length {
		chunkLen := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
		if chunkLen < 6 || offset+chunkLen > length {
			return nil
		}
		chunkType := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		if chunkType == ChunkPayload {
			return packet[offset+6 : offset+chunkLen]
		}
		offset += chunkLen
	}
	return nil
}
