package decoder

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"

	"github.com/negbie/heplify/config"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
)

var (
	d1q     layers.Dot1Q
	eth     layers.Ethernet
	ip4     layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	sip     SIP
	payload gopacket.Payload
	decoded = []gopacket.LayerType{}
)

/* type Packet struct {
	Ts   time.Time `json:"ts"`
	Host string    `json:"host,omitempty"`
	Ip4  *IPv4     `json:"ip4,omitempty"`
	Ip6  *IPv6     `json:"ip6,omitempty"`
	Tcp  *TCP      `json:"tcp,omitempty"`
	Udp  *UDP      `json:"udp,omitempty"`
	Hep  *Hep      `json:"-"`
} */

type Decoder struct {
	Host string
}

type Packet struct {
	Host      string
	Tsec      uint32
	Tmsec     uint32
	Smac      []byte
	Dmac      []byte
	Vlan      uint16
	Srcip     uint32
	Dstip     uint32
	Sport     uint16
	Dport     uint16
	Payload   []byte
	SipHeader map[string][]string
}

func NewDecoder() *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return &Decoder{Host: host}
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &d1q, &ip4, &tcp, &udp, &sip, &payload)
	parser.DecodeLayers(data, &decoded)

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			pkt.Smac = eth.SrcMAC
			pkt.Dmac = eth.DstMAC

		case layers.LayerTypeDot1Q:
			pkt.Vlan = d1q.VLANIdentifier

		case layers.LayerTypeIPv4:
			pkt.Srcip = ip2int(ip4.SrcIP)
			pkt.Dstip = ip2int(ip4.DstIP)

		case layers.LayerTypeUDP:
			pkt.Sport = uint16(udp.SrcPort)
			pkt.Dport = uint16(udp.DstPort)

		case layers.LayerTypeTCP:
			pkt.Sport = uint16(tcp.SrcPort)
			pkt.Dport = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload

		case gopacket.LayerTypePayload:
			if config.Cfg.HepFilter != "" && bytes.Contains(payload.Payload(), []byte(config.Cfg.HepFilter)) {
				return nil, nil
			}
			pkt.Payload = payload.Payload()
			sipParser := gopacket.NewPacket(payload, LayerTypeSIP, gopacket.NoCopy)
			sipLayer, ok := sipParser.Layers()[0].(*SIP)
			if !ok {
				break
			}
			pkt.SipHeader = sipLayer.Headers
		}
	}
	return pkt, nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
