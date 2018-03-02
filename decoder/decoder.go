package decoder

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/freecache"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

type Decoder struct {
	Host          string
	NodeID        uint32
	NodePW        []byte
	LayerType     gopacket.LayerType
	defragger     *ip4defrag.IPv4Defragmenter
	fragCount     int
	dupCount      int
	dnsCount      int
	ip4Count      int
	ip6Count      int
	rtcpCount     int
	rtcpFailCount int
	tcpCount      int
	udpCount      int
	unknownCount  int
	FlowSrcIP     string
	FlowDstIP     string
	FlowSrcPort   string
	FlowDstPort   string
	SIPCache      *freecache.Cache
	SDPCache      *freecache.Cache
	RTCPCache     *freecache.Cache
}

type Packet struct {
	Host          string
	NodeID        uint32
	NodePW        []byte
	Tsec          uint32
	Tmsec         uint32
	Vlan          uint16
	Version       byte
	Protocol      byte
	ProtoType     byte
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	CorrelationID []byte
	Payload       []byte
}

func NewDecoder(datalink layers.LinkType) *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = "heplify-host"
	}
	var lt gopacket.LayerType

	switch datalink {
	case layers.LinkTypeEthernet:
		lt = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		lt = layers.LayerTypeLinuxSLL
	default:
		lt = layers.LayerTypeEthernet
	}

	cSIP := freecache.NewCache(20 * 1024 * 1024)  // 20MB
	cSDP := freecache.NewCache(20 * 1024 * 1024)  // 20MB
	cRTCP := freecache.NewCache(30 * 1024 * 1024) // 30MB
	//debug.SetGCPercent(20)

	d := &Decoder{
		Host:      host,
		NodeID:    uint32(config.Cfg.HepNodeID),
		NodePW:    []byte(config.Cfg.HepNodePW),
		LayerType: lt,
		defragger: ip4defrag.NewIPv4Defragmenter(),
		SIPCache:  cSIP,
		SDPCache:  cSDP,
		RTCPCache: cRTCP,
	}
	go d.flushFragments()
	go d.printStats()
	return d
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:   d.Host,
		NodeID: d.NodeID,
		NodePW: d.NodePW,
		Tsec:   uint32(ci.Timestamp.Unix()),
		Tmsec:  uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	if len(data) > 42 {
		if config.Cfg.Dedup {
			_, err := d.SIPCache.Get(data[42:])
			if err == nil {
				d.dupCount++
				return nil, nil
			}
			err = d.SIPCache.Set(data[42:], nil, 1)
			if err != nil {
				logp.Warn("%v", err)
			}
		}
		if config.Cfg.Filter != "" {
			if !bytes.Contains(data[42:], []byte(config.Cfg.Filter)) {
				return nil, nil
			}
		}
		if config.Cfg.Discard != "" {
			if bytes.Contains(data[42:], []byte(config.Cfg.Discard)) {
				return nil, nil
			}
		}
		logp.Debug("payload", "\n%v", string(data[42:]))
	}

	packet := gopacket.NewPacket(data, d.LayerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	logp.Debug("layer", "\n%v", packet)

	if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
		gre, ok := greLayer.(*layers.GRE)
		if !ok {
			return nil, nil
		}

		if config.Cfg.Iface.WithErspan {
			packet = gopacket.NewPacket(gre.Payload[8:], d.LayerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		} else {
			packet = gopacket.NewPacket(gre.Payload, d.LayerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		}
		logp.Debug("layer", "\nlayer inside GRE\n%v", packet)
	}

	if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, ok := dot1qLayer.(*layers.Dot1Q)
		if !ok {
			return nil, nil
		}
		pkt.Vlan = dot1q.VLANIdentifier
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ip4, ok := ipv4Layer.(*layers.IPv4)
		ip4Len := ip4.Length
		if !ok {
			return nil, nil
		}

		pkt.Version = 0x02
		pkt.Protocol = uint8(ip4.Protocol)
		pkt.SrcIP = ip4.SrcIP
		pkt.DstIP = ip4.DstIP
		d.ip4Count++

		d.FlowSrcIP = ip4.SrcIP.String()
		d.FlowDstIP = ip4.DstIP.String()

		ip4New, err := d.defragger.DefragIPv4(ip4)
		if err != nil {
			logp.Warn("%v", err)
			return nil, nil
		} else if ip4New == nil {
			d.fragCount++
			return nil, nil
		}

		if ip4New.Length != ip4Len {
			logp.Debug("fragment", "Fragmented packet layers:\n%v\nFragmented packet payload:\n%v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
				packet, string(packet.ApplicationLayer().Payload()), string(ip4New.Payload[8:]), ip4New.Length,
			)

			pkt.Version = 0x02
			pkt.Protocol = uint8(ip4New.Protocol)
			pkt.SrcIP = ip4New.SrcIP
			pkt.DstIP = ip4New.DstIP

			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				logp.Critical("Not a PacketBuilder")
			}
			nextDecoder := ip4New.NextLayerType()
			nextDecoder.Decode(ip4New.Payload, pb)
		}
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ip6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return nil, nil
		}

		pkt.Version = 0x0a
		pkt.Protocol = uint8(ip6.NextHeader)
		pkt.SrcIP = ip6.SrcIP
		pkt.DstIP = ip6.DstIP
		d.ip6Count++

		d.FlowSrcIP = ip6.SrcIP.String()
		d.FlowDstIP = ip6.DstIP.String()
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil, nil
		}

		if bytes.Contains(udp.Payload, []byte("sip")) {
			pkt.ProtoType = 1
		}
		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.Payload = udp.Payload
		d.udpCount++

		d.FlowSrcPort = fmt.Sprintf("%d", udp.SrcPort)
		d.FlowDstPort = fmt.Sprintf("%d", udp.DstPort)

		if config.Cfg.Mode == "SIPLOG" {
			if udp.DstPort == 514 {
				//d.cacheCallID(udp.Payload)
				pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateLOG(udp.Payload)
				if pkt.Payload != nil {
					return pkt, nil
				}
				return nil, nil
			} else if udp.SrcPort == 2223 || udp.DstPort == 2223 {
				pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateNG(udp.Payload)
				if pkt.Payload != nil {
					return pkt, nil
				}
				return nil, nil
			}
		}
		if config.Cfg.Mode != "SIP" {
			d.cacheSDPIPPort(udp.Payload)
			if (udp.Payload[0]&0xc0)>>6 == 2 {
				if (udp.Payload[1] == 200 || udp.Payload[1] == 201 || udp.Payload[1] == 207) && udp.SrcPort%2 != 0 && udp.DstPort%2 != 0 {
					pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateRTCP(udp.Payload)
					if pkt.Payload != nil {
						d.rtcpCount++
						return pkt, nil
					}
					d.rtcpFailCount++
					return nil, nil
				} else if udp.SrcPort%2 == 0 && udp.DstPort%2 == 0 {
					logp.Debug("rtp", "\n%v", protos.NewRTP(udp.Payload))
					pkt.Payload = nil
					return nil, nil
				}
			}
		}
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, nil
		}

		if bytes.Contains(tcp.Payload, []byte("sip")) {
			pkt.ProtoType = 1
		}
		pkt.SrcPort = uint16(tcp.SrcPort)
		pkt.DstPort = uint16(tcp.DstPort)
		pkt.Payload = tcp.Payload
		d.tcpCount++

		if config.Cfg.Mode == "SIPLOG" && tcp.DstPort == 514 {
			pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateLOG(tcp.Payload)
			if pkt.Payload != nil {
				return pkt, nil
			}
			return nil, nil
		}
		if config.Cfg.Mode != "SIP" {
			d.cacheSDPIPPort(tcp.Payload)
		}
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, ok := dnsLayer.(*layers.DNS)
		if !ok {
			return nil, nil
		}

		pkt.ProtoType = 53
		pkt.Payload = protos.ParseDNS(dns)
		d.dnsCount++
	}

	if pkt.Payload != nil {
		return pkt, nil
	}

	d.unknownCount++
	return nil, nil
}
