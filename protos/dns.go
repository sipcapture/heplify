package protos

import (
	"net"

	"github.com/google/gopacket/layers"
	"github.com/negbie/logp"
	"github.com/segmentio/encoding/json"
)

type DNS struct {
	ID     uint16           `json:"id"`
	QR     bool             `json:"qr"`
	OpCode layers.DNSOpCode `json:"opcode"`

	AA bool  `json:"aa"` // Authoritative answer
	TC bool  `json:"tc"` // Truncated
	RD bool  `json:"rd"` // Recursion desired
	RA bool  `json:"ra"` // Recursion available
	Z  uint8 `json:"z"`  // For future use

	ResponseCode layers.DNSResponseCode `json:"rescode"`
	QDCount      uint16                 `json:"qdc"` // Expected questions
	ANCount      uint16                 `json:"anc"` // Expected answers
	NSCount      uint16                 `json:"nsc"` // Expected authorities
	ARCount      uint16                 `json:"arc"` // Expected additional records

	Questions []DNSQuestion       `json:"questions,omitempty"`
	Answers   []DNSResourceRecord `json:"answers,omitempty"`
}

type DNSQuestion struct {
	Name  string          `json:"name"`
	Type  layers.DNSType  `json:"type"`
	Class layers.DNSClass `json:"class"`
}

type DNSResourceRecord struct {
	Name  string          `json:"name"`
	Type  layers.DNSType  `json:"type"`
	Class layers.DNSClass `json:"class"`
	TTL   uint32          `json:"ttl"`

	IP    net.IP `json:"ip,omitempty"`
	NS    string `json:"ns,omitempty"`
	CNAME string `json:"cname,omitempty"`
}

func newDNS(dns *layers.DNS) (d *DNS) {
	d = &DNS{}

	d.ID = dns.ID
	d.QR = dns.QR
	d.OpCode = dns.OpCode

	d.AA = dns.AA
	d.TC = dns.TC
	d.RD = dns.RD
	d.RA = dns.RA
	d.Z = dns.Z

	d.ResponseCode = dns.ResponseCode
	d.QDCount = dns.QDCount
	d.ANCount = dns.ANCount
	d.NSCount = dns.NSCount
	d.ARCount = dns.ARCount

	for _, q := range dns.Questions {
		qs := DNSQuestion{}
		qs.Name = string(q.Name)
		qs.Type = q.Type
		qs.Class = q.Class
		d.Questions = append(d.Questions, qs)
	}

	for _, r := range dns.Answers {
		res := DNSResourceRecord{}
		res.Name = string(r.Name)
		res.Type = r.Type
		res.Class = r.Class
		res.TTL = r.TTL

		res.IP = r.IP
		res.NS = string(r.NS)
		res.CNAME = string(r.CNAME)

		d.Answers = append(d.Answers, res)
	}

	return d
}

func (d *DNS) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(*d)
	return bytes, err
}

func ParseDNS(d *layers.DNS) []byte {
	dns, err := newDNS(d).MarshalJSON()
	if err != nil {
		logp.Warn("%v", err)
		return nil
	}
	logp.Debug("dns", "Payload=%v", string(dns))
	return dns
}
