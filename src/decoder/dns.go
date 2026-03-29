package decoder

import (
	"encoding/json"

	"github.com/google/gopacket/layers"
)

// DNSQuestion represents a DNS query question
type DNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// DNSAnswer represents a DNS resource record
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	IP    string `json:"ip,omitempty"`
	NS    string `json:"ns,omitempty"`
	CNAME string `json:"cname,omitempty"`
	PTR   string `json:"ptr,omitempty"`
	TXT   string `json:"txt,omitempty"`
}

// DNSReport is the JSON representation of a parsed DNS packet
type DNSReport struct {
	ID           uint16        `json:"id"`
	QR           bool          `json:"qr"`
	OpCode       string        `json:"opcode"`
	AA           bool          `json:"aa"`
	TC           bool          `json:"tc"`
	RD           bool          `json:"rd"`
	RA           bool          `json:"ra"`
	Z            uint8         `json:"z"`
	ResponseCode string        `json:"rcode"`
	Questions    []DNSQuestion `json:"questions,omitempty"`
	Answers      []DNSAnswer   `json:"answers,omitempty"`
}

// ParseDNS parses a raw DNS payload and returns JSON bytes.
// Returns nil on error.
func ParseDNS(data []byte) []byte {
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(data, nil); err != nil {
		return nil
	}

	report := DNSReport{
		ID:           dns.ID,
		QR:           dns.QR,
		OpCode:       dns.OpCode.String(),
		AA:           dns.AA,
		TC:           dns.TC,
		RD:           dns.RD,
		RA:           dns.RA,
		Z:            dns.Z,
		ResponseCode: dns.ResponseCode.String(),
	}

	for _, q := range dns.Questions {
		report.Questions = append(report.Questions, DNSQuestion{
			Name:  string(q.Name),
			Type:  q.Type.String(),
			Class: q.Class.String(),
		})
	}

	for _, rr := range dns.Answers {
		a := DNSAnswer{
			Name:  string(rr.Name),
			Type:  rr.Type.String(),
			Class: rr.Class.String(),
			TTL:   rr.TTL,
		}
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			a.IP = rr.IP.String()
		case layers.DNSTypeNS:
			a.NS = string(rr.NS)
		case layers.DNSTypeCNAME:
			a.CNAME = string(rr.CNAME)
		case layers.DNSTypePTR:
			a.PTR = string(rr.PTR)
		case layers.DNSTypeTXT:
			if len(rr.TXTs) > 0 {
				a.TXT = string(rr.TXTs[0])
			}
		}
		report.Answers = append(report.Answers, a)
	}

	out, err := json.Marshal(&report)
	if err != nil {
		return nil
	}
	return out
}
