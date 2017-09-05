package decoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/negbie/heplify/config"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
)

var eth layers.Ethernet
var ip4 layers.IPv4
var tcp layers.TCP
var udp layers.UDP
var payload gopacket.Payload

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
	Host    string
	Tsec    uint32
	Tmsec   uint32
	Srcip   uint32
	Dstip   uint32
	Sport   uint16
	Dport   uint16
	Payload []byte
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

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &payload)
	decoded := []gopacket.LayerType{}
	parser.DecodeLayers(data, &decoded)

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			pkt.Payload = eth.Payload
			
		case layers.LayerTypeIPv4:
			pkt.Srcip = ip2int(ip4.SrcIP)
			pkt.Dstip = ip2int(ip4.DstIP)

		case layers.LayerTypeUDP:
			if config.Cfg.HepFilter != "" && bytes.Contains(udp.Payload, []byte(config.Cfg.HepFilter)) {
				return nil, nil
			}
			//pkt.Udp = NewUDP(udp)
			pkt.Sport = uint16(udp.SrcPort)
			pkt.Dport = uint16(udp.DstPort)
			pkt.Payload = udp.Payload

			/*
				p := gopacket.NewPacket(layer.LayerPayload(), LayerTypeSIP, gopacket.NoCopy)
				sipLayer, ok := p.Layers()[0].(*SIP)
				fmt.Println(sipLayer)
				if !ok {
					break
				}
			*/

			return pkt, nil

		case layers.LayerTypeTCP:
			if config.Cfg.HepFilter != "" && bytes.Contains(tcp.Payload, []byte(config.Cfg.HepFilter)) {
				return nil, nil
			}
			//pkt.Tcp = NewTCP(tcp)
			pkt.Sport = uint16(tcp.SrcPort)
			pkt.Dport = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload

			return pkt, nil

		default:

			if payload != nil {
				fmt.Println(layerType)

				pkt.Payload = payload.Payload()
				fmt.Println(string(pkt.Payload))
			}
		}
	}
	return nil, nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
