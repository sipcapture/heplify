package decoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
)

type Decoder struct {
	Host      string
	defragger *ip4defrag.IPv4Defragmenter
}

type Packet struct {
	Host      string
	Tsec      uint32
	Tmsec     uint32
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
	return &Decoder{Host: host, defragger: ip4defrag.NewIPv4Defragmenter()}
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if packet.ErrorLayer() != nil {
		fmt.Println("Failed to decode packet:", packet.ErrorLayer().Error())
	}
	if app := packet.ApplicationLayer(); app != nil {
		if config.Cfg.HepFilter != "" && bytes.Contains(app.Payload(), []byte(config.Cfg.HepFilter)) {
			return nil, nil
		}
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4l := packet.Layer(layers.LayerTypeIPv4)
		ip4, ok := ip4l.(*layers.IPv4)
		ip4Len := ip4.Length
		if !ok {
			return nil, nil
		}

		ip4Defrag, err := d.defragger.DefragIPv4WithTimestamp(ip4, ci.Timestamp)
		//ip4Defrag, err := d.defragger.DefragIPv4(ip4)
		if err != nil {
			return nil, nil
		}
		if ip4Defrag == nil {
			return nil, nil
		}
		pkt.Srcip = ip2int(ip4Defrag.SrcIP)
		pkt.Dstip = ip2int(ip4Defrag.DstIP)

		if ip4Defrag.Length > ip4Len {
			ip4Header := ip4.LayerContents()
			ip4Header[2] = byte((len(ip4Defrag.LayerPayload()) + 20) / 256)
			ip4Header[3] = byte((len(ip4Defrag.LayerPayload()) + 20) % 256)
			ip4Header[6] = 0
			ip4Header[7] = 0

			// Build new defragmentated Packet
			newIP4 := append(ip4Header, ip4Defrag.LayerPayload()...)
			data := append(packet.Data()[0:14], newIP4...)
			packet = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			//fmt.Println(ip4Defrag.SrcIP.String())
			//fmt.Println(ip4Defrag.DstIP.String())
		}

	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcpl := packet.Layer(layers.LayerTypeTCP)
		tcp, ok := tcpl.(*layers.TCP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(tcp.SrcPort)
		pkt.Dport = uint16(tcp.DstPort)
		pkt.Payload = tcp.Payload

		/* p := gopacket.NewPacket(layer.LayerPayload(), LayerTypeSIP, gopacket.NoCopy)
		   sipLayer, ok := p.Layers()[0].(*SIP)
		   if !ok {
			   break
		   }
		   pkt.SipHeader = sipLayer.Headers */
		return pkt, nil
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udpl := packet.Layer(layers.LayerTypeUDP)
		udp, ok := udpl.(*layers.UDP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(udp.SrcPort)
		pkt.Dport = uint16(udp.DstPort)
		pkt.Payload = udp.Payload

		/* p := gopacket.NewPacket(layer.LayerPayload(), LayerTypeSIP, gopacket.NoCopy)
		   sipLayer, ok := p.Layers()[0].(*SIP)
		   if !ok {
			   break
		   }
		   pkt.SipHeader = sipLayer.Headers */
		return pkt, nil
	}

	return nil, nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
