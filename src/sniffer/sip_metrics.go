package sniffer

import (
	"bytes"
	"net"
	"strings"

	"github.com/sipcapture/heplify/src/config"
)

const defaultCarrier = "other"

var knownSIPMethods = map[string]struct{}{
	"ACK":       {},
	"BYE":       {},
	"CANCEL":    {},
	"INFO":      {},
	"INVITE":    {},
	"MESSAGE":   {},
	"NOTIFY":    {},
	"OPTIONS":   {},
	"PRACK":     {},
	"PUBLISH":   {},
	"REFER":     {},
	"REGISTER":  {},
	"SUBSCRIBE": {},
	"UPDATE":    {},
}

type sipMetric struct {
	Method      string
	IsResponse  bool
	StatusCode  string
	StatusClass string
}

func parseSIPMetric(payload []byte) (sipMetric, bool) {
	line, _, _ := bytes.Cut(payload, []byte("\r\n"))
	if len(line) == 0 {
		return sipMetric{}, false
	}

	if bytes.HasPrefix(line, []byte("SIP/2.0 ")) {
		fields := bytes.Fields(line)
		if len(fields) < 2 || len(fields[1]) != 3 {
			return sipMetric{}, false
		}
		code := string(fields[1])
		for i := 0; i < len(code); i++ {
			if code[i] < '0' || code[i] > '9' {
				return sipMetric{}, false
			}
		}
		return sipMetric{
			Method:      parseCSeqMethod(payload),
			IsResponse:  true,
			StatusCode:  code,
			StatusClass: code[:1] + "xx",
		}, true
	}

	fields := bytes.Fields(line)
	if len(fields) < 3 || !bytes.Equal(fields[len(fields)-1], []byte("SIP/2.0")) {
		return sipMetric{}, false
	}
	return sipMetric{Method: normalizeSIPMethod(string(fields[0]))}, true
}

func parseCSeqMethod(payload []byte) string {
	headers, _, _ := bytes.Cut(payload, []byte("\r\n\r\n"))
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !bytes.EqualFold(bytes.TrimSpace(name), []byte("CSeq")) {
			continue
		}
		fields := bytes.Fields(value)
		if len(fields) < 2 {
			return "UNKNOWN"
		}
		return normalizeSIPMethod(string(fields[1]))
	}
	return "UNKNOWN"
}

func normalizeSIPMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if _, ok := knownSIPMethods[method]; ok {
		return method
	}
	return "UNKNOWN"
}

type carrierResolver struct {
	entries []carrierEntry
}

type carrierEntry struct {
	name string
	nets []*net.IPNet
}

func newCarrierResolver(settings []config.CarrierSettings) *carrierResolver {
	resolver := &carrierResolver{}
	for _, setting := range settings {
		name := strings.TrimSpace(setting.Name)
		if name == "" {
			continue
		}
		entry := carrierEntry{name: name}
		for _, cidr := range setting.CIDRs {
			_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			entry.nets = append(entry.nets, network)
		}
		if len(entry.nets) > 0 {
			resolver.entries = append(resolver.entries, entry)
		}
	}
	return resolver
}

func (r *carrierResolver) Resolve(srcIP, dstIP net.IP) string {
	if r == nil {
		return defaultCarrier
	}
	if carrier := r.lookup(srcIP); carrier != "" {
		return carrier
	}
	if carrier := r.lookup(dstIP); carrier != "" {
		return carrier
	}
	return defaultCarrier
}

func (r *carrierResolver) lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, entry := range r.entries {
		for _, network := range entry.nets {
			if network.Contains(ip) {
				return entry.name
			}
		}
	}
	return ""
}
