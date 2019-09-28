package protos

import (
	"encoding/binary"
	"fmt"
	"io"
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
}

// Errors used by ReadWSHeader.
var (
	ErrHeaderLengthMSB        = fmt.Errorf("header error: the most significant bit must be 0")
	ErrHeaderLengthUnexpected = fmt.Errorf("header error: unexpected payload length bits")
)

// ReadWSHeader reads a Websocket header from r.
func ReadWSHeader(r io.Reader) (h WSHeader, err error) {
	bts := make([]byte, 2, 14)

	_, err = io.ReadFull(r, bts)
	if err != nil {
		return
	}

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
	_, err = io.ReadFull(r, bts)
	if err != nil {
		return
	}

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

	if h.Masked {
		copy(h.Mask[:], bts)
	}

	return
}

// WSPayload returns the Websocket payload from r.
func WSPayload(r io.Reader) (b []byte, err error) {
	header, err := ReadWSHeader(r)
	if err != nil {
		return
	}

	if header.Length > 0 {
		b = make([]byte, int(header.Length))
		_, err = io.ReadFull(r, b)
	}

	return
}
