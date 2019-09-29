package protos

import (
	"encoding/binary"
	"fmt"
)

// WSOpCode represents operation code.
type WSOpCode byte

// WSHeader represents a Websocket header.
type WSHeader struct {
	Fin    bool
	Rsv    byte
	OpCode WSOpCode
	Masked bool
	Mask   [4]byte
	Length int64
	Offset int
}

// Errors used by ReadWSHeader.
var (
	ErrHeaderLengthMSB        = fmt.Errorf("ws header most significant bit must be 0")
	ErrHeaderLengthUnexpected = fmt.Errorf("ws header unexpected payload length bits")
)

// ReadWSHeader reads a Websocket header from r.
func ReadWSHeader(data []byte) (h WSHeader, err error) {
	l := len(data)
	bts := make([]byte, 2, 14)
	n := copy(bts, data)

	h.Fin = bts[0]&0x80 != 0
	h.Rsv = (bts[0] & 0x70) >> 4
	h.OpCode = WSOpCode(bts[0] & 0x0f)

	var extra int

	if bts[1]&0x80 != 0 {
		h.Masked = true
		extra += 4
	}

	length := bts[1] & 0x7f
	switch {
	case length < 126:
		h.Length = int64(length)

	case length == 126:
		extra += 2

	case length == 127:
		extra += 8

	default:
		err = ErrHeaderLengthUnexpected
		return
	}

	if extra == 0 {
		return
	}

	bts = bts[:extra]
	data = data[n:]
	n = copy(bts, data)
	h.Offset = n + 2

	switch {
	case length == 126:
		h.Length = int64(binary.BigEndian.Uint16(bts[:2]))
		bts = bts[2:]

	case length == 127:
		if bts[0]&0x80 != 0 {
			err = ErrHeaderLengthMSB
			return
		}
		h.Length = int64(binary.BigEndian.Uint64(bts[:8]))
		bts = bts[8:]
	}

	if l-h.Offset != int(h.Length) {
		err = ErrHeaderLengthUnexpected
		return
	}

	if h.Masked {
		copy(h.Mask[:], bts)
	}

	return
}

// WSPayload returns the Websocket payload from r.
func WSPayload(data []byte) (b []byte, err error) {
	h, err := ReadWSHeader(data)
	if err != nil {
		return
	}

	if h.Length > 0 {
		b = make([]byte, int(h.Length))
		copy(b, data[h.Offset:])
	}

	if h.Masked {
		n := len(b)
		for i := 0; i < n; i++ {
			b[i] ^= h.Mask[(i)%4]
		}
	}

	return
}
