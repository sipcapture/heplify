package protos

import (
	"github.com/negbie/heplify/logp"
	"github.com/negbie/tlsx"
)

type TLSHandshake struct {
	tlsx.TLSMessage
	HandshakeType    uint8
	HandshakeLen     uint32
	HandshakeVersion tlsx.Version
	Random           []byte
	SessionIDLen     uint32
	SessionID        []byte
	CipherSuiteLen   uint16
	CipherSuites     []tlsx.CipherSuite
	CompressMethods  []uint8
	ExtensionLen     uint16
	Extensions       map[tlsx.Extension]uint16
	SNI              string
	SignatureAlgs    []uint16
	SupportedGroups  []uint16
	SupportedPoints  []uint8
	OSCP             bool
	ALPNs            []string
}

// TODO: complete this
func NewTLS(raw []byte) []byte {
	var hello = tlsx.ClientHello{}
	err := hello.Unmarshall(raw)

	switch err {
	case nil:
		logp.Info("Captured TLS handshake:\n%v\n", hello.String())
		return []byte(hello.String())
	case tlsx.ErrHandshakeWrongType:
		return nil
	default:
		return nil
	}
}
