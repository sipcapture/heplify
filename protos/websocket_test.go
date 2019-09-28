package protos

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	OpText   WSOpCode = 0x1
	OpBinary WSOpCode = 0x2
	OpClose  WSOpCode = 0x8
	OpPing   WSOpCode = 0x9
	OpPong   WSOpCode = 0xa
)

type WSTestCase struct {
	Data   []byte
	Header WSHeader
	Err    bool
}

var WSTestCases = []WSTestCase{
	{
		Data: bits("1 001 0001 0 1100100"),
		//          _ ___ ____ _ _______
		//          |  |   |   |    |
		//         Fin |   |  Mask Length
		//            Rsv  |
		//             TextFrame
		Header: WSHeader{
			Fin:    true,
			Rsv:    rsv(false, false, true),
			OpCode: OpText,
			Length: 100,
		},
	},
	{
		Data: bits("1 001 0001 1 1100100 00000001 10001000 00000000 11111111"),
		//          _ ___ ____ _ _______ ___________________________________
		//          |  |   |   |    |                     |
		//         Fin |   |  Mask Length             Mask value
		//            Rsv  |
		//             TextFrame
		Header: WSHeader{
			Fin:    true,
			Rsv:    rsv(false, false, true),
			OpCode: OpText,
			Length: 100,
			Masked: true,
			Mask:   [4]byte{0x01, 0x88, 0x00, 0xff},
		},
	},
	{
		Data: bits("0 110 0010 0 1111110 00001111 11111111"),
		//          _ ___ ____ _ _______ _________________
		//          |  |   |   |    |            |
		//         Fin |   |  Mask Length   Length value
		//            Rsv  |
		//             BinaryFrame
		Header: WSHeader{
			Fin:    false,
			Rsv:    rsv(true, true, false),
			OpCode: OpBinary,
			Length: 0x0fff,
		},
	},
	{
		Data: bits("1 000 1010 0 1111111 01111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000"),
		//          _ ___ ____ _ _______ _______________________________________________________________________
		//          |  |   |   |    |                                       |
		//         Fin |   |  Mask Length                              Length value
		//            Rsv  |
		//              PongFrame
		Header: WSHeader{
			Fin:    true,
			Rsv:    rsv(false, false, false),
			OpCode: OpPong,
			Length: 0x7f00000000000000,
		},
	},
}

func TestReadWSHeader(t *testing.T) {
	for i, test := range append([]WSTestCase{
		{
			Data: bits("0000 0000 0 1111111 10000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"),
			//                              _______________________________________________________________________
			//                                                                 |
			//                                                            Length value
			Err: true,
		},
	}, WSTestCases...) {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			h, err := ReadWSHeader(bytes.NewReader(test.Data))
			if test.Err && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !test.Err && err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if test.Err {
				return
			}
			if !reflect.DeepEqual(h, test.Header) {
				t.Errorf("ReadWSHeader(bytes.NewReader(test.Data))\nread:\n\t%#v\nwant:\n\t%#v", h, test.Header)
			}
		})
	}
}

func bits(s string) []byte {
	s = strings.Replace(s, " ", "", -1)
	bts := make([]byte, len(s)/8)

	for i, j := 0, 0; i < len(s); i, j = i+8, j+1 {
		fmt.Sscanf(s[i:], "%08b", &bts[j])
	}

	return bts
}

func rsv(r1, r2, r3 bool) (rsv byte) {
	if r1 {
		rsv |= 0x04
	}
	if r2 {
		rsv |= 0x02
	}
	if r3 {
		rsv |= 0x01
	}
	return rsv
}
