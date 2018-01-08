package decoder

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/coocood/freecache"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

type Decoder struct {
	Host            string
	Node            uint32
	LayerType       gopacket.LayerType
	defragger       *ip4defrag.IPv4Defragmenter
	eth             layers.Ethernet
	sll             layers.LinuxSLL
	dot1q           layers.Dot1Q
	ip4             layers.IPv4
	ip6             layers.IPv6
	udp             layers.UDP
	tcp             layers.TCP
	dns             layers.DNS
	payload         gopacket.Payload
	foundLayerTypes []gopacket.LayerType
	FlowSrcIP       string
	FlowDstIP       string
	FlowSrcPort     string
	FlowDstPort     string
	SIPCache        *freecache.Cache
	SDPCache        *freecache.Cache
	RTCPCache       *freecache.Cache
	Stats
}

type Stats struct {
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
}

type Packet struct {
	Host          string
	Node          uint32
	Tsec          uint32
	Tmsec         uint32
	Vlan          uint16
	Version       uint8
	Protocol      uint8
	ProtoType     uint8
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
	cRTCP := freecache.NewCache(40 * 1024 * 1024) // 40MB
	//debug.SetGCPercent(20)

	d := &Decoder{
		Host:            host,
		Node:            uint32(config.Cfg.HepNodeID),
		LayerType:       lt,
		defragger:       ip4defrag.NewIPv4Defragmenter(),
		SIPCache:        cSIP,
		SDPCache:        cSDP,
		RTCPCache:       cRTCP,
		foundLayerTypes: make([]gopacket.LayerType, 0, 10),
	}

	go d.flushFragments()
	go d.printStats()
	return d
}

func (d *Decoder) defragIPv4(ip4frag layers.IPv4) (ip4 *layers.IPv4, err error) {
	return d.defragger.DefragIPv4(&ip4frag)
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Node:  d.Node,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	logp.Debug("raw", "\n%x", data)

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

	parser := gopacket.NewDecodingLayerParser(d.LayerType, &d.eth, &d.sll, &d.dot1q, &d.ip4, &d.ip6, &d.udp, &d.tcp, &d.dns, &d.payload)
	logp.Debug("layer", "found following layers %v", d.foundLayerTypes)

	err := parser.DecodeLayers(data, &d.foundLayerTypes)
	if err != nil {
		logp.Debug("layerwarn", "%v but found following layers %v with payload [%s]", err, d.foundLayerTypes, string(data))
	}

	for _, layerType := range d.foundLayerTypes {
		switch layerType {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d.dot1q.VLANIdentifier

		case layers.LayerTypeIPv4:
			pkt.Version = d.ip4.Version
			pkt.Protocol = uint8(d.ip4.Protocol)
			pkt.SrcIP = d.ip4.SrcIP
			pkt.DstIP = d.ip4.DstIP
			d.ip4Count++

			d.FlowSrcIP = d.ip4.SrcIP.String()
			d.FlowDstIP = d.ip4.DstIP.String()

			if d.ip4.Flags&layers.IPv4DontFragment == 0 && (d.ip4.Flags&layers.IPv4MoreFragments != 0 || d.ip4.FragOffset != 0) {
				ip4New, err := d.defragIPv4(d.ip4)
				if err != nil {
					logp.Warn("%v", err)
					return nil, nil
				} else if ip4New == nil {
					d.fragCount++
					return nil, nil
				}
				logp.Debug("fragment", "Fragmented packet layers %v with payload %v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
					d.foundLayerTypes, string(d.ip4.Payload), string(ip4New.Payload[8:]), ip4New.Length,
				)

				pkt.Version = ip4New.Version
				pkt.Protocol = uint8(ip4New.Protocol)
				pkt.SrcIP = ip4New.SrcIP
				pkt.DstIP = ip4New.DstIP

				if ip4New.Protocol == layers.IPProtocolUDP {
					parserOnlyUDP := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &d.udp)
					parserOnlyUDP.DecodeLayers(ip4New.Payload, &d.foundLayerTypes)
				} else if ip4New.Protocol == layers.IPProtocolTCP {
					parserOnlyTCP := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &d.tcp)
					parserOnlyTCP.DecodeLayers(ip4New.Payload, &d.foundLayerTypes)
				} else {
					// Protocol not supported
					return nil, nil
				}
			}

		case layers.LayerTypeIPv6:
			pkt.Version = d.ip6.Version
			pkt.Protocol = uint8(d.ip6.NextHeader)
			pkt.SrcIP = d.ip6.SrcIP
			pkt.DstIP = d.ip6.DstIP
			d.ip6Count++

			d.FlowSrcIP = d.ip6.SrcIP.String()
			d.FlowDstIP = d.ip6.DstIP.String()

		case layers.LayerTypeUDP:
			pkt.SrcPort = uint16(d.udp.SrcPort)
			pkt.DstPort = uint16(d.udp.DstPort)
			pkt.Payload = d.udp.Payload
			d.udpCount++

			d.FlowSrcPort = fmt.Sprintf("%d", d.udp.SrcPort)
			d.FlowDstPort = fmt.Sprintf("%d", d.udp.DstPort)

			if config.Cfg.Mode != "SIP" {
				d.cacheSDPIPPort(d.udp.Payload)
				if (d.udp.Payload[0]&0xc0)>>6 == 2 {
					if (d.udp.Payload[1] >= 200 && d.udp.Payload[1] <= 207) && d.udp.SrcPort%2 != 0 && d.udp.DstPort%2 != 0 {
						pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateRTCP(d.udp.Payload)
						if pkt.Payload != nil {
							d.rtcpCount++
							return pkt, nil
						}
						d.rtcpFailCount++
						return nil, nil
					} else if d.udp.SrcPort%2 == 0 && d.udp.DstPort%2 == 0 {
						logp.Debug("rtp", "\n%v", protos.NewRTP(d.udp.Payload))
						pkt.Payload = nil
						return nil, nil
					}
				}
			}
			if config.Cfg.Mode == "SIPLOG" {
				//d.cacheCallID(udp.Payload)
				if d.udp.DstPort == 514 {
					pkt.Payload, pkt.CorrelationID, pkt.ProtoType = d.correlateLOG(d.udp.Payload)
					if pkt.Payload != nil {
						return pkt, nil
					}
				}
			}
			if bytes.Contains(d.udp.Payload, []byte("sip")) {
				pkt.ProtoType = 1
			}

		case layers.LayerTypeTCP:
			pkt.SrcPort = uint16(d.tcp.SrcPort)
			pkt.DstPort = uint16(d.tcp.DstPort)
			pkt.Payload = d.tcp.Payload
			d.tcpCount++

			if config.Cfg.Mode != "SIP" {
				d.cacheSDPIPPort(d.tcp.Payload)
			}
			if bytes.Contains(d.tcp.Payload, []byte("sip")) {
				pkt.ProtoType = 1
			}

		case layers.LayerTypeDNS:
			pkt.ProtoType = 53
			pkt.Payload = protos.ParseDNS(&d.dns)
			d.dnsCount++
		}
	}

	if pkt.Payload != nil {
		return pkt, nil
	}

	d.unknownCount++
	return nil, nil
}
