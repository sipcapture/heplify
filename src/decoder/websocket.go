package decoder

import (
	"encoding/binary"
	"fmt"
)

// WebSocket opcodes
const (
	WSOpCodeContinuation = 0x0
	WSOpCodeText         = 0x1
	WSOpCodeBinary       = 0x2
	WSOpCodeClose        = 0x8
	WSOpCodePing         = 0x9
	WSOpCodePong         = 0xA
)

// WSHeader represents a WebSocket frame header
type WSHeader struct {
	Fin    bool
	Rsv    byte
	OpCode byte
	Masked bool
	Mask   [4]byte
	Length int64
	Offset int
}

// Errors for WebSocket parsing
var (
	ErrWSHeaderLengthMSB        = fmt.Errorf("ws header most significant bit must be 0")
	ErrWSHeaderLengthUnexpected = fmt.Errorf("ws header unexpected payload length bits")
	ErrWSHeaderTooShort         = fmt.Errorf("ws header too short")
)

// ReadWSHeader reads a WebSocket header from data
func ReadWSHeader(data []byte) (WSHeader, error) {
	h := WSHeader{}

	if len(data) < 2 {
		return h, ErrWSHeaderTooShort
	}

	h.Fin = data[0]&0x80 != 0
	h.Rsv = (data[0] & 0x70) >> 4
	h.OpCode = data[0] & 0x0F

	if data[1]&0x80 != 0 {
		h.Masked = true
	}

	length := data[1] & 0x7F
	switch {
	case length < 126:
		h.Length = int64(length)
		h.Offset = 2

	case length == 126:
		if len(data) < 4 {
			return h, ErrWSHeaderTooShort
		}
		h.Length = int64(binary.BigEndian.Uint16(data[2:4]))
		h.Offset = 4

	case length == 127:
		if len(data) < 10 {
			return h, ErrWSHeaderTooShort
		}
		if data[2]&0x80 != 0 {
			return h, ErrWSHeaderLengthMSB
		}
		h.Length = int64(binary.BigEndian.Uint64(data[2:10]))
		h.Offset = 10

	default:
		return h, ErrWSHeaderLengthUnexpected
	}

	if h.Masked {
		if len(data) < h.Offset+4 {
			return h, ErrWSHeaderTooShort
		}
		copy(h.Mask[:], data[h.Offset:h.Offset+4])
		h.Offset += 4
	}

	return h, nil
}

// WSPayload extracts and unmasks WebSocket payload
func WSPayload(data []byte) ([]byte, error) {
	h, err := ReadWSHeader(data)
	if err != nil {
		return nil, err
	}

	if int64(len(data)) < int64(h.Offset)+h.Length {
		return nil, ErrWSHeaderTooShort
	}

	payload := make([]byte, h.Length)
	copy(payload, data[h.Offset:int64(h.Offset)+h.Length])

	if h.Masked {
		for i := range payload {
			payload[i] ^= h.Mask[i%4]
		}
	}

	return payload, nil
}

// IsWebSocketUpgrade checks if HTTP data is a WebSocket upgrade request/response
func IsWebSocketUpgrade(data []byte) bool {
	// Check for HTTP request/response
	if len(data) < 4 {
		return false
	}

	// Check for GET or HTTP
	if string(data[:3]) != "GET" && string(data[:4]) != "HTTP" {
		return false
	}

	// Look for WebSocket upgrade header
	for i := 0; i < len(data)-20; i++ {
		if data[i] == 'U' || data[i] == 'u' {
			if matchCaseInsensitive(data[i:], []byte("Upgrade: websocket")) {
				return true
			}
		}
	}

	return false
}

// IsWebSocketFrame checks if data looks like a WebSocket frame
func IsWebSocketFrame(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check for valid opcode and frame structure
	opcode := data[0] & 0x0F
	if opcode > 0x0A || (opcode > 0x02 && opcode < 0x08) {
		return false
	}

	// Text or binary frames: check length bits (lower 7 of byte 1)
	lengthBits := data[1] & 0x7F
	if (data[0] == 0x81 || data[0] == 0x82) && (lengthBits <= 126 || lengthBits == 127) {
		return true
	}

	return false
}

// ExtractSIPFromWebSocket extracts SIP message from WebSocket frame
func ExtractSIPFromWebSocket(data []byte) ([]byte, error) {
	payload, err := WSPayload(data)
	if err != nil {
		return nil, err
	}

	// Check if payload looks like SIP
	if !IsSIPMessage(payload) {
		return nil, fmt.Errorf("payload is not SIP")
	}

	return payload, nil
}

// IsSIPMessage checks if data looks like a SIP message
func IsSIPMessage(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for SIP request methods
	sipMethods := []string{
		"INVITE ",
		"REGISTER ",
		"ACK ",
		"BYE ",
		"CANCEL ",
		"OPTIONS ",
		"PRACK ",
		"SUBSCRIBE ",
		"NOTIFY ",
		"PUBLISH ",
		"INFO ",
		"REFER ",
		"MESSAGE ",
		"UPDATE ",
	}

	for _, method := range sipMethods {
		if len(data) >= len(method) && string(data[:len(method)]) == method {
			return true
		}
	}

	// Check for SIP response
	if len(data) >= 8 && string(data[:7]) == "SIP/2.0" {
		return true
	}

	return false
}

func matchCaseInsensitive(data, pattern []byte) bool {
	if len(data) < len(pattern) {
		return false
	}

	for i := 0; i < len(pattern); i++ {
		d := data[i]
		p := pattern[i]

		// Convert to lowercase for comparison
		if d >= 'A' && d <= 'Z' {
			d += 32
		}
		if p >= 'A' && p <= 'Z' {
			p += 32
		}

		if d != p {
			return false
		}
	}

	return true
}
