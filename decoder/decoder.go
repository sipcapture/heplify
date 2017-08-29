package decoder

import (
	"encoding/binary"
	"net"
	"os"
	"time"

	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
)

type Packet struct {
	Ts   time.Time `json:"ts"`
	Host string    `json:"host,omitempty"`
	Ip4  *IPv4     `json:"ip4,omitempty"`
	Ip6  *IPv6     `json:"ip6,omitempty"`
	Tcp  *TCP      `json:"tcp,omitempty"`
	Udp  *UDP      `json:"udp,omitempty"`
	Hep  *Hep      `json:"-"`
}

type Decoder struct {
	Host string
}

type Hep struct {
	Tsec     uint32
	Tmsec    uint32
	Srcip    uint32
	Dstip    uint32
	Sport    uint16
	Dport    uint16
	Payload  []byte
	Protocol layers.IPProtocol
}

func NewDecoder() *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return &Decoder{Host: host}
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	hep := &Hep{
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}
	pkt := &Packet{
		Host: d.Host,
		Ts:   ci.Timestamp,
		Hep:  hep,
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			ip4l := packet.Layer(layers.LayerTypeIPv4)
			ip4, ok := ip4l.(*layers.IPv4)
			if !ok {
				return nil, nil
			}
			pkt.Ip4 = NewIP4(ip4)
			hep.Srcip = ip2int(ip4.SrcIP)
			hep.Dstip = ip2int(ip4.DstIP)
			hep.Protocol = ip4.Protocol

		case layers.LayerTypeIPv6:
			ip6l := packet.Layer(layers.LayerTypeIPv6)
			ip6, ok := ip6l.(*layers.IPv6)
			if !ok {
				return nil, nil
			}
			pkt.Ip6 = NewIP6(ip6)

			hep.Srcip = ip2int(ip6.SrcIP)
			hep.Dstip = ip2int(ip6.DstIP)
			hep.Protocol = ip6.NextHeader

		case layers.LayerTypeUDP:
			udpl := packet.Layer(layers.LayerTypeUDP)
			udp, ok := udpl.(*layers.UDP)
			if !ok {
				break
			}
			pkt.Udp = NewUDP(udp)
			hep.Sport = uint16(udp.SrcPort)
			hep.Dport = uint16(udp.DstPort)
			hep.Payload = udp.Payload
			return pkt, nil
		case layers.LayerTypeTCP:
			tcpl := packet.Layer(layers.LayerTypeTCP)
			tcp, ok := tcpl.(*layers.TCP)
			if !ok {
				break
			}
			pkt.Tcp = NewTCP(tcp)
			hep.Sport = uint16(tcp.SrcPort)
			hep.Dport = uint16(tcp.DstPort)
			hep.Payload = tcp.Payload
			return pkt, nil
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
