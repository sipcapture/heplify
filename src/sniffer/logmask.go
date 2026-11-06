package sniffer

import (
	"bytes"
	"strings"
)

// maskedSIPHeaders hold credentials that must not end up in debug logs.
var maskedSIPHeaders = [][]byte{
	[]byte("authorization"),
	[]byte("proxy-authorization"),
}

// maskSIPCredentials returns payload as a string with the values of
// Authorization and Proxy-Authorization headers replaced by the auth scheme
// followed by "***". Only the header section is changed.
func maskSIPCredentials(payload []byte) string {
	end := bytes.Index(payload, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(payload)
	}
	headers := payload[:end]
	if !containsFold(headers, []byte("authorization")) {
		return string(payload)
	}
	var b strings.Builder
	b.Grow(len(payload))
	rest := headers
	for len(rest) > 0 {
		line := rest
		next := []byte(nil)
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, next = rest[:i+1], rest[i+1:]
		}
		rest = next
		if colon := bytes.IndexByte(line, ':'); colon > 0 && isMaskedHeader(bytes.TrimSpace(line[:colon])) {
			val := bytes.TrimSpace(line[colon+1:])
			scheme := val
			if sp := bytes.IndexByte(val, ' '); sp >= 0 {
				scheme = val[:sp]
			}
			b.Write(line[:colon+1])
			b.WriteByte(' ')
			b.Write(scheme)
			b.WriteString(" ***")
			if bytes.HasSuffix(line, []byte("\r\n")) {
				b.WriteString("\r\n")
			} else if bytes.HasSuffix(line, []byte("\n")) {
				b.WriteByte('\n')
			}
			continue
		}
		b.Write(line)
	}
	b.Write(payload[end:])
	return b.String()
}

func isMaskedHeader(name []byte) bool {
	for _, h := range maskedSIPHeaders {
		if bytes.EqualFold(name, h) {
			return true
		}
	}
	return false
}

func containsFold(s, sub []byte) bool {
	return bytes.Contains(bytes.ToLower(s), sub)
}
