package decoder

import (
	"encoding/binary"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	//"github.com/negbie/sippar"
	//"github.com/negbie/siprocket"
)

type Decoder struct {
	Host          string
	defragger     *ip4defrag.IPv4Defragmenter
	defragCounter int
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
	//SipMsg  *sipparser.SipMsg
	//SipMsg siprocket.SipMsg
	//SipHeader map[string][]string
}

func NewDecoder() *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = "sniffer"
	}
	return &Decoder{Host: host, defragger: ip4defrag.NewIPv4Defragmenter(), defragCounter: 0}
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	//logp.Debug("decoder", "Captured packet layers:\n%v\nCaptured packet payload:\n%v\n", packet, string(packet.ApplicationLayer().Payload()))

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4l := packet.Layer(layers.LayerTypeIPv4)
		ip4, ok := ip4l.(*layers.IPv4)
		ip4Len := ip4.Length
		if !ok {
			return nil, nil
		}

		if config.Cfg.Reasm {
			ip4, err := d.defragger.DefragIPv4WithTimestamp(ip4, ci.Timestamp)
			if err != nil {
				logp.Err("Error while de-fragmenting", err)
				return nil, err
			} else if ip4 == nil {
				//packet fragment, we don't have whole packet yet
				return nil, nil
			}

			if ip4.Length != ip4Len {
				d.defragCounter++

				if d.defragCounter%128 == 0 {
					logp.Info("Defragmentated packet counter: %d", d.defragCounter)
				}
				//logp.Info("Decoding re-assembled packet: %v\n next layer: %s\n", packet, ip4.NextLayerType())
				logp.Info("Decoding fragmented packet layers:\n%v\nFragmented packet payload:\n%v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
					packet, string(packet.ApplicationLayer().Payload()), string(ip4.Payload[8:]), ip4.Length,
				)
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
		return pkt, nil
	}

	/* 	// SIP parser. Right now not needed
	   	if appLayer := packet.ApplicationLayer(); appLayer != nil {
	   		if config.Cfg.HepFilter != "" && bytes.Contains(appLayer.Payload(), []byte(config.Cfg.HepFilter)) {
	   			return nil, nil
	   		}

	   		sipl := gopacket.NewPacket(appLayer.Payload(), LayerTypeSIP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	   		sip, ok := sipl.Layers()[0].(*SIP)
	   		if !ok {
	   			return nil, nil
	   		}
	   		pkt.Payload = appLayer.Payload()
	   		//pkt.SipMsg = sipparser.ParseMsg(string(udp.Payload))
	   		//pkt.SipMsg = siprocket.Parse(udp.payload)
	   		pkt.SipHeader = sip.Headers
	   		return pkt, nil
	   	}
	*/

	return nil, nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
