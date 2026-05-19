package transport

import (
	"encoding/hex"
	"errors"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/sipcapture/heplify/src/hep"
)

func isMessageTooLong(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EMSGSIZE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "message too long")
}

func enrichMessageTooLongLog(ev *zerolog.Event, hepPacket []byte, wireBytes int, printBody bool) *zerolog.Event {
	payload := hep.PayloadBytes(hepPacket)
	ev = ev.Int("hep_bytes", len(hepPacket)).
		Int("wire_bytes", wireBytes).
		Int("hep_payload_bytes", len(payload))
	if !printBody {
		return ev
	}
	const maxHex = 512
	const maxText = 8192
	if len(payload) > 0 {
		ev = ev.Str("hep_payload_hex", hexEncodeLimit(payload, maxHex))
		if printableASCII(payload) {
			ev = ev.Str("hep_payload", stringLimit(payload, maxText))
		}
	}
	if len(hepPacket) > 0 {
		ev = ev.Str("hep_packet_hex", hexEncodeLimit(hepPacket, maxHex))
	}
	return ev
}

func hexEncodeLimit(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > max {
		b = b[:max]
	}
	return hex.EncodeToString(b)
}

func stringLimit(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

func printableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\r' && c != '\n' && c != '\t' {
			return false
		}
		if c > 0x7e {
			return false
		}
	}
	return true
}
