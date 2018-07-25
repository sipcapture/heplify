package decoder

import (
	"bytes"
	"net"
	"runtime/debug"
	"strings"
	"time"

	"github.com/coocood/freecache"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/ip6defrag"
	"github.com/negbie/heplify/protos"
	"github.com/negbie/logp"
)

type Decoder struct {
	asm       *reassembly.Assembler
	defrag4   *ip4defrag.IPv4Defragmenter
	defrag6   *ip6defrag.IPv6Defragmenter
	parser    *gopacket.DecodingLayerParser
	layerType gopacket.LayerType
	nodeID    uint32
	nodePW    []byte
	filter    []string
	stats
}

type stats struct {
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
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	NodeID    uint32
	NodePW    []byte
	Payload   []byte
	CID       []byte
	Vlan      uint16
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

var sll layers.LinuxSLL
var d1q layers.Dot1Q
var gre layers.GRE
var eth layers.Ethernet
var ip4 layers.IPv4
var ip6 layers.IPv6
var ip6frag layers.IPv6Fragment
var tcp layers.TCP
var udp layers.UDP
var dns layers.DNS
var payload gopacket.Payload

var netFlow gopacket.Flow
var decodedLayers = make([]gopacket.LayerType, 0, 12)

var PacketQueue = make(chan *Packet, 20000)

var SIPCache = freecache.NewCache(20 * 1024 * 1024)  // 20 MB
var SDPCache = freecache.NewCache(30 * 1024 * 1024)  // 30 MB
var RTCPCache = freecache.NewCache(30 * 1024 * 1024) // 30 MB

func NewDecoder(datalink layers.LinkType) *Decoder {
	var lt gopacket.LayerType
	switch datalink {
	case layers.LinkTypeEthernet:
		lt = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		lt = layers.LayerTypeLinuxSLL
	default:
		lt = layers.LayerTypeEthernet
	}

	// TODO: make a flag for this
	debug.SetGCPercent(50)

	streamFactory := &tcpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	decoder := gopacket.NewDecodingLayerParser(
		lt, &sll, &d1q, &gre, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload,
	)

	d := &Decoder{
		asm:       assembler,
		defrag4:   ip4defrag.NewIPv4Defragmenter(),
		defrag6:   ip6defrag.NewIPv6Defragmenter(),
		parser:    decoder,
		nodeID:    uint32(config.Cfg.HepNodeID),
		nodePW:    []byte(config.Cfg.HepNodePW),
		layerType: lt,
		filter:    strings.Split(strings.ToUpper(config.Cfg.DiscardMethod), ","),
	}

	go d.flushFragments()
	go d.printStats()
	return d
}

func (d *Decoder) defragIP4(i4 layers.IPv4, t time.Time) (*layers.IPv4, error) {
	return d.defrag4.DefragIPv4WithTimestamp(&i4, t)
}

func (d *Decoder) defragIP6(i6 layers.IPv6, i6frag layers.IPv6Fragment, t time.Time) (*layers.IPv6, error) {
	return d.defrag6.DefragIPv6WithTimestamp(&i6, &i6frag, t)
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) {
	pkt := &Packet{
		NodeID: d.nodeID,
		NodePW: d.nodePW,
		Tsec:   uint32(ci.Timestamp.Unix()),
		Tmsec:  uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	if config.Cfg.Dedup {
		if len(data) > 384 {
			_, err := SIPCache.Get(data[42:])
			if err == nil {
				d.dupCount++
				return
			}
			err = SIPCache.Set(data[42:], nil, 1)
			if err != nil {
				logp.Warn("%v", err)
			}
		}
	}

	if config.Cfg.DiscardMethod != "" {
		c := parseCSeq(data)
		if c != nil {
			for _, v := range d.filter {
				if string(c) == v {
					return
				}
			}
		}
	}

	d.parser.DecodeLayers(data, &decodedLayers)
	logp.Debug("layer", "\n%v", decodedLayers)
	foundIPLayer := false
	foundGRELayer := false

	for i := 0; i < len(decodedLayers); i++ {
		switch decodedLayers[i] {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d1q.VLANIdentifier

		case layers.LayerTypeGRE:
			if config.Cfg.Iface.WithErspan {
				d.parser.DecodeLayers(gre.Payload[8:], &decodedLayers)
				if !foundGRELayer {
					i = 0
				}
				foundGRELayer = true

			} else {
				d.parser.DecodeLayers(gre.Payload, &decodedLayers)
				if !foundGRELayer {
					i = 0
				}
				foundGRELayer = true
			}

		case layers.LayerTypeIPv4:
			ip4Len := ip4.Length
			pkt.Version = 0x02
			pkt.Protocol = uint8(ip4.Protocol)
			pkt.SrcIP = ip4.SrcIP
			pkt.DstIP = ip4.DstIP
			d.ip4Count++

			ip4New, err := d.defragIP4(ip4, ci.Timestamp)
			if err != nil {
				logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, pkt.SrcIP.String(), pkt.DstIP.String())
				return
			} else if ip4New == nil {
				d.fragCount++
				return
			}

			if ip4New.Length != ip4Len {
				logp.Debug("fragment", "fragment layer: %v with payload:\n%s\nre-assembled payload:\n%s\nRe-assembled packet length:\n%d\n\n",
					decodedLayers, ip4.Payload, ip4New.Payload[8:], ip4New.Length,
				)

				pkt.Version = 0x02
				pkt.Protocol = uint8(ip4New.Protocol)
				pkt.SrcIP = ip4New.SrcIP
				pkt.DstIP = ip4New.DstIP

				if ip4New.Protocol == layers.IPProtocolUDP {
					nextUDP := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
					nextUDP.DecodeLayers(ip4New.Payload, &decodedLayers)
				} else if ip4New.Protocol == layers.IPProtocolTCP {
					nextTCP := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
					nextTCP.DecodeLayers(ip4New.Payload, &decodedLayers)
				} else {
					// Protocol not supported
					return
				}
			}
			netFlow = ip4.NetworkFlow()
			foundIPLayer = true

		case layers.LayerTypeIPv6:
			ip6Len := ip6.Length
			pkt.Version = 0x0a
			pkt.Protocol = uint8(ip6.NextHeader)
			pkt.SrcIP = ip6.SrcIP
			pkt.DstIP = ip6.DstIP
			d.ip6Count++

			for _, lt := range decodedLayers {
				if lt == layers.LayerTypeIPv6Fragment {
					ip6New, err := d.defragIP6(ip6, ip6frag, ci.Timestamp)
					if err != nil {
						logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, pkt.SrcIP.String(), pkt.DstIP.String())
						return
					} else if ip6New == nil {
						d.fragCount++
						return
					}

					if ip6New.Length != ip6Len {
						logp.Debug("fragment", "fragment layer: %v with payload:\n%s\nre-assembled payload:\n%s\nRe-assembled packet length:\n%d\n\n",
							decodedLayers, ip6.Payload, ip6New.Payload[8:], ip6New.Length,
						)

						pkt.Version = 0x0a
						pkt.Protocol = uint8(ip6New.NextHeader)
						pkt.SrcIP = ip6New.SrcIP
						pkt.DstIP = ip6New.DstIP

						if ip6New.NextHeader == layers.IPProtocolUDP {
							nextUDP := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
							nextUDP.DecodeLayers(ip6New.Payload, &decodedLayers)
						} else if ip6New.NextHeader == layers.IPProtocolTCP {
							nextTCP := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
							nextTCP.DecodeLayers(ip6New.Payload, &decodedLayers)
						} else {
							// Protocol not supported
							return
						}
					}
				}
			}

			netFlow = ip6.NetworkFlow()
			foundIPLayer = true

		case layers.LayerTypeUDP:
			logp.Debug("payload", "\n%s", udp.Payload)
			if len(udp.Payload) < 16 {
				logp.Warn("received too small UDP packet with len %d", len(udp.Payload))
				return
			}

			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
			pkt.Payload = udp.Payload
			d.udpCount++

			if config.Cfg.Mode == "SIPLOG" {
				if udp.DstPort == 514 {
					pkt.Payload, pkt.CID, pkt.ProtoType = correlateLOG(udp.Payload)
					if pkt.Payload != nil && pkt.CID != nil {
						PacketQueue <- pkt
					}
					return
				} else if udp.SrcPort == 2223 || udp.DstPort == 2223 {
					pkt.Payload, pkt.CID, pkt.ProtoType = correlateNG(udp.Payload)
					if pkt.Payload != nil {
						PacketQueue <- pkt
					}
					return
				}
			}
			if config.Cfg.Mode != "SIP" {
				cacheSDPIPPort(udp.Payload)
				if (udp.Payload[0]&0xc0)>>6 == 2 {
					if (udp.Payload[1] == 200 || udp.Payload[1] == 201 || udp.Payload[1] == 207) && udp.SrcPort%2 != 0 && udp.DstPort%2 != 0 {
						pkt.Payload, pkt.CID, pkt.ProtoType = correlateRTCP(pkt.SrcIP, pkt.SrcPort, udp.Payload)
						if pkt.Payload != nil {
							d.rtcpCount++
							PacketQueue <- pkt
							return
						}
						d.rtcpFailCount++
						return
					} else if udp.SrcPort%2 == 0 && udp.DstPort%2 == 0 {
						logp.Debug("rtp", "\n%v", protos.NewRTP(udp.Payload))
						pkt.Payload = nil
						return
					}
				}
			}

		case layers.LayerTypeTCP:
			logp.Debug("payload", "\n%s", tcp.Payload)
			d.tcpCount++
			if foundIPLayer {
				c := Context{
					CaptureInfo: *ci,
				}
				d.asm.AssembleWithContext(netFlow, &tcp, &c)
			}
			return

		case layers.LayerTypeDNS:
			if config.Cfg.Mode == "SIPDNS" {
				pkt.ProtoType = 53
				pkt.Payload = protos.ParseDNS(&dns)
				d.dnsCount++
				PacketQueue <- pkt
				return
			}
		}
	}

	if bytes.Contains(pkt.Payload, []byte("CSeq")) {
		pkt.ProtoType = 1
	} else if bytes.Contains(pkt.Payload, []byte("Cseq")) {
		pkt.ProtoType = 1
	}

	if pkt.Payload != nil {
		PacketQueue <- pkt
	} else {
		d.unknownCount++
	}
}
