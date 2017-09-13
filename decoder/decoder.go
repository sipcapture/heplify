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
	//"github.com/negbie/tlsx"
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
	MF      bool
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
	logp.Debug("decoder", "Captured packet layers:\n %v\n", packet)

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4, ok := ipLayer.(*layers.IPv4)
		ip4Len := ip4.Length
		pkt.MF = false
		if !ok {
			return nil, nil
		}
		if (ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) && ip4Len >= 576 {
			pkt.MF = true
		}

		pkt.Srcip = ip2int(ip4.SrcIP)
		pkt.Dstip = ip2int(ip4.DstIP)

		if config.Cfg.Reasm {
			if ip4.Flags&layers.IPv4DontFragment == 0 && (ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) {
				ip4New, err := d.defragger.DefragIPv4WithTimestamp(ip4, ci.Timestamp)
				if err != nil {
					logp.Err("Error while de-fragmenting", err)
					return nil, err
				} else if ip4New == nil {
					//packet fragment, we don't have whole packet yet. Send it anyway and overwrite it later
					return nil, nil
				}

				if ip4New.Length != ip4Len {
					d.defragCounter++

					if d.defragCounter%128 == 0 {
						logp.Warn("Defragmentated packet counter: %d", d.defragCounter)
					}
					logp.Info("Decoding fragmented packet layers:\n%v\nFragmented packet payload:\n%v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
						packet, string(packet.ApplicationLayer().Payload()), string(ip4New.Payload[8:]), ip4New.Length,
					)

					pb, ok := packet.(gopacket.PacketBuilder)
					if !ok {
						panic("Not a PacketBuilder")
					}
					nextDecoder := ip4New.NextLayerType()
					nextDecoder.Decode(ip4New.Payload, pb)
				}
				pkt.Srcip = ip2int(ip4New.SrcIP)
				pkt.Dstip = ip2int(ip4New.DstIP)
			}
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(tcp.SrcPort)
		pkt.Dport = uint16(tcp.DstPort)
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(udp.SrcPort)
		pkt.Dport = uint16(udp.DstPort)
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if pkt.Sport == 0 {
			pkt.Sport = 5060
		}
		if pkt.Dport == 0 {
			pkt.Dport = 5060
		}
		if pkt.MF {
			pkt.Payload = appLayer.Payload()[8:]
		} else {
			pkt.Payload = appLayer.Payload()
		}
		return pkt, nil
	}

	/* // TLS handshake parser. Right now not needed
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if pkt.Dport == 443 || pkt.Sport == 443 {
			var hello = tlsx.ClientHello{}

			err := hello.Unmarshall(appLayer.Payload())

			switch err {
			case nil:
				fmt.Println(hello)
			case tlsx.ErrHandshakeWrongType:
				return nil, nil
			default:
				fmt.Println("Error reading Client Hello:", err)
				fmt.Println("Raw Client Hello:", appLayer.Payload())
				return nil, nil
			}
		}
	}
	*/

	/* // SIP parser. Right now not needed
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
