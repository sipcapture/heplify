package decoder

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/logp"
)

type Decoder struct {
	Host      string
	defragger *ip4defrag.IPv4Defragmenter
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
	//SipHeader map[string][]string
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

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4l := packet.Layer(layers.LayerTypeIPv4)
		ip4, ok := ip4l.(*layers.IPv4)
		ip4Len := ip4.Length
		if !ok {
			return nil, nil
		}
		if config.Cfg.HepFilter != "" && bytes.Contains(ip4.Payload, []byte(config.Cfg.HepFilter)) {
			return nil, nil
		}
		if ip4.Flags&layers.IPv4DontFragment == 0 && (ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) {
			ip4, err := d.defragger.DefragIPv4(ip4)
			if err != nil {
				logp.Err("Error while de-fragmenting", err)
			} else if ip4 == nil {
				logp.Notice("packet fragment, we don't have whole packet yet")
				return nil, nil
			}

			if ip4.Length != ip4Len {
				logp.Notice("Decoding re-assembled packet: %s\n", ip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := ip4.NextLayerType()
				nextDecoder.Decode(ip4.Payload, pb)
			}
		}
		pkt.Srcip = ip2int(ip4.SrcIP)
		pkt.Dstip = ip2int(ip4.DstIP)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcpl := packet.Layer(layers.LayerTypeTCP)
			tcp, ok := tcpl.(*layers.TCP)
			if !ok {
				return nil, nil
			}
			pkt.Sport = uint16(tcp.SrcPort)
			pkt.Dport = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload

			/* 			p := gopacket.NewPacket(tcp.Payload, LayerTypeSIP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			   			sipLayer, ok := p.Layers()[0].(*SIP)
			   			if !ok {
			   				return nil, nil
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
			/* 			if udp.Length > 1500 {
				fmt.Println(udp.Length)
				fmt.Println(string(udp.Payload))
			} */

			/* 			p := gopacket.NewPacket(udp.Payload, LayerTypeSIP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			   			sipLayer, ok := p.Layers()[0].(*SIP)
			   			if !ok {
			   				return nil, nil
			   			}
			   			pkt.SipHeader = sipLayer.Headers */
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
