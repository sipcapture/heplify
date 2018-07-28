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
	"github.com/google/gopacket/tcpassembly"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/ip6defrag"
	"github.com/negbie/heplify/protos"
	"github.com/negbie/logp"
)

type Decoder struct {
	asm       *tcpassembly.Assembler
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
var tcp layers.TCP
var udp layers.UDP
var dns layers.DNS
var payload gopacket.Payload

var decodedLayers = make([]gopacket.LayerType, 0, 12)
var parserOnlyUDP = gopacket.NewDecodingLayerParser(
	layers.LayerTypeUDP,
	&udp,
)
var parserOnlyTCP = gopacket.NewDecodingLayerParser(
	layers.LayerTypeTCP,
	&tcp,
)

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

	streamFactory := &sipStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = 1
	assembler.MaxBufferedPagesTotal = 1

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
	if config.Cfg.Dedup {
		if len(data) > 384 {
			_, err := SIPCache.Get(data[34:])
			if err == nil {
				d.dupCount++
				return
			}
			err = SIPCache.Set(data[34:], nil, 1)
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
	foundGRELayer := false

	for i := 0; i < len(decodedLayers); i++ {
		switch decodedLayers[i] {
		case layers.LayerTypeGRE:
			if config.Cfg.Iface.WithErspan {
				if len(gre.Payload) > 8 {
					d.parser.DecodeLayers(gre.Payload[8:], &decodedLayers)
					if !foundGRELayer {
						i = 0
					}
					foundGRELayer = true
				}
			} else {
				d.parser.DecodeLayers(gre.Payload, &decodedLayers)
				if !foundGRELayer {
					i = 0
				}
				foundGRELayer = true
			}

		case layers.LayerTypeIPv4:
			ip4Len := ip4.Length
			d.ip4Count++

			ip4New, err := d.defragIP4(ip4, ci.Timestamp)
			if err != nil {
				logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, ip4.SrcIP, ip4.DstIP)
				return
			} else if ip4New == nil {
				d.fragCount++
				return
			}

			if ip4New.Length == ip4Len {
				d.processTransport(&decodedLayers, &udp, &tcp, ip4.NetworkFlow(), ci, 0x02, uint8(ip4.Protocol), ip4.SrcIP, ip4.DstIP)
			} else {
				logp.Debug("fragment", "%d byte fragment layer: %s with payload:\n%s\n%d byte re-assembled payload:\n%s\n\n",
					ip4Len, decodedLayers, ip4.Payload, ip4New.Length, ip4New.Payload,
				)

				if ip4New.Protocol == layers.IPProtocolUDP {
					parserOnlyUDP.DecodeLayers(ip4New.Payload, &decodedLayers)
				} else if ip4New.Protocol == layers.IPProtocolTCP {
					parserOnlyTCP.DecodeLayers(ip4New.Payload, &decodedLayers)
				} else {
					logp.Warn("unsupported ipv4fragment layer")
					return
				}
				d.processTransport(&decodedLayers, &udp, &tcp, ip4New.NetworkFlow(), ci, 0x02, uint8(ip4New.Protocol), ip4New.SrcIP, ip4New.DstIP)
			}

		case layers.LayerTypeIPv6:
			ip6Len := ip6.Length
			d.ip6Count++

			if ip6.NextHeader != layers.IPProtocolIPv6Fragment {
				d.processTransport(&decodedLayers, &udp, &tcp, ip6.NetworkFlow(), ci, 0x0a, uint8(ip6.NextHeader), ip6.SrcIP, ip6.DstIP)
			} else {
				packet := gopacket.NewPacket(data, d.layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
				if ip6frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ip6frag != nil {
					ip6New, err := d.defragIP6(ip6, *ip6frag, ci.Timestamp)
					if err != nil {
						logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, ip6.SrcIP, ip6.DstIP)
						return
					} else if ip6New == nil {
						d.fragCount++
						return
					}

					logp.Debug("fragment", "%d byte fragment layer: %s with payload:\n%s\n%d byte re-assembled payload:\n%s\n\n",
						ip6Len, decodedLayers, ip6.Payload, ip6New.Length, ip6New.Payload,
					)

					if ip6New.NextHeader == layers.IPProtocolUDP {
						parserOnlyUDP.DecodeLayers(ip6New.Payload, &decodedLayers)
					} else if ip6New.NextHeader == layers.IPProtocolTCP {
						parserOnlyTCP.DecodeLayers(ip6New.Payload, &decodedLayers)
					} else {
						logp.Warn("unsupported ipv6fragment layer")
						return
					}
					d.processTransport(&decodedLayers, &udp, &tcp, ip6New.NetworkFlow(), ci, 0x0a, uint8(ip6New.NextHeader), ip6New.SrcIP, ip6New.DstIP)
				}
			}
		}
	}
}

func (d *Decoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, flow gopacket.Flow, ci *gopacket.CaptureInfo, IPVersion, IPProtocol uint8, sIP, dIP net.IP) {
	pkt := &Packet{
		Version:  IPVersion,
		Protocol: IPProtocol,
		SrcIP:    sIP,
		DstIP:    dIP,
		NodeID:   d.nodeID,
		NodePW:   d.nodePW,
		Tsec:     uint32(ci.Timestamp.Unix()),
		Tmsec:    uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	for _, layerType := range *foundLayerTypes {
		switch layerType {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d1q.VLANIdentifier

		case layers.LayerTypeUDP:
			if len(udp.Payload) < 16 {
				logp.Warn("received too small %d byte UDP packet with payload %s", len(udp.Payload), udp.Payload)
				return
			}

			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
			pkt.Payload = udp.Payload
			d.udpCount++
			logp.Debug("payload", "UDP:\n%s", pkt)

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
						if config.Cfg.Mode == "SIPRTP" {
							logp.Debug("rtp", "\n%v", protos.NewRTP(udp.Payload))
						}
						pkt.Payload = nil
						return
					}
				}
			}

		case layers.LayerTypeTCP:
			pkt.SrcPort = uint16(tcp.SrcPort)
			pkt.DstPort = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload
			d.tcpCount++
			logp.Debug("payload", "TCP:\n%s", pkt)

			if config.Cfg.Reassembly {
				d.asm.AssembleWithTimestamp(flow, tcp, ci.Timestamp)
				return
			}

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
