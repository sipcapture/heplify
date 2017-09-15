package protos

import (
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

func NewTLS(tls *tlsx.ClientHello) (t *TLSHandshake) {
	t = &TLSHandshake{}
	return t
}
