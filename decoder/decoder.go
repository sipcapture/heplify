package decoder

import (
	"bytes"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/negbie/freecache"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/decoder/internal"
	"github.com/sipcapture/heplify/ip4defrag"
	"github.com/sipcapture/heplify/ip6defrag"
	"github.com/sipcapture/heplify/ownlayers"
	"github.com/sipcapture/heplify/protos"
)

var PacketQueue = make(chan *Packet, 20000)

type Decoder struct {
	asm           *tcpassembly.Assembler
	defrag4       *ip4defrag.IPv4Defragmenter
	defrag6       *ip6defrag.IPv6Defragmenter
	layerType     gopacket.LayerType
	decodedLayers []gopacket.LayerType
	parser        *gopacket.DecodingLayerParser
	parserUDP     *gopacket.DecodingLayerParser
	parserTCP     *gopacket.DecodingLayerParser
	sll           layers.LinuxSLL
	d1q           layers.Dot1Q
	gre           layers.GRE
	eth           layers.Ethernet
	vxl           ownlayers.VXLAN
	hperm         ownlayers.HPERM
	ip4           layers.IPv4
	ip6           layers.IPv6
	tcp           layers.TCP
	udp           layers.UDP
	dns           layers.DNS
	sctp          layers.SCTP
	payload       gopacket.Payload
	dedupCache    *freecache.Cache
	filter        []string
	filterSrcIP   []string
	stats
}

type stats struct {
	_             uint32
	fragCount     uint64
	dupCount      uint64
	dnsCount      uint64
	ip4Count      uint64
	ip6Count      uint64
	rtcpCount     uint64
	rtcpFailCount uint64
	tcpCount      uint64
	sctpCount     uint64
	udpCount      uint64
	unknownCount  uint64
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

	/* 	decoder := gopacket.NewDecodingLayerParser(
		lt, &sll, &d1q, &gre, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload,
	) */
	d := &Decoder{}
	dlp := gopacket.NewDecodingLayerParser(lt)
	dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	dlp.AddDecodingLayer(&d.sll)
	dlp.AddDecodingLayer(&d.d1q)
	dlp.AddDecodingLayer(&d.gre)
	dlp.AddDecodingLayer(&d.eth)
	dlp.AddDecodingLayer(&d.vxl)
	//dlp.AddDecodingLayer(&d.hperm)
	dlp.AddDecodingLayer(&d.ip4)
	dlp.AddDecodingLayer(&d.ip6)
	dlp.AddDecodingLayer(&d.sctp)
	dlp.AddDecodingLayer(&d.udp)
	dlp.AddDecodingLayer(&d.tcp)
	dlp.AddDecodingLayer(&d.dns)
	dlp.AddDecodingLayer(&d.payload)

	d.parser = dlp
	d.layerType = lt
	d.defrag4 = ip4defrag.NewIPv4Defragmenter()
	d.defrag6 = ip6defrag.NewIPv6Defragmenter()
	d.decodedLayers = make([]gopacket.LayerType, 0, 12)
	d.parserUDP = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &d.udp)
	d.parserTCP = gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &d.tcp)

	d.filter = strings.Split(strings.ToUpper(config.Cfg.DiscardMethod), ",")
	d.filterSrcIP = strings.Split(config.Cfg.DiscardSrcIP, ",")

	if config.Cfg.Dedup {
		d.dedupCache = freecache.NewCache(20 * 1024 * 1024) // 20 MB
	}

	if config.Cfg.Reassembly {
		streamFactory := &tcpStreamFactory{}
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		d.asm = tcpassembly.NewAssembler(streamPool)
		d.asm.MaxBufferedPagesPerConnection = 1
		d.asm.MaxBufferedPagesTotal = 1
		go d.flushTCPAssembler(1 * time.Second)
	}

	go d.flushFragments(1 * time.Minute)
	go d.printStats(1 * time.Minute)
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
		if len(data) > 34 {
			_, err := d.dedupCache.Get(data[34:])
			if err == nil {
				atomic.AddUint64(&d.dupCount, 1)
				return
			}
			err = d.dedupCache.Set(data[34:], nil, 4) // 400 ms expire time
			if err != nil {
				logp.Warn("%v", err)
			}
		}
	}

	if config.Cfg.DiscardMethod != "" {
		c := internal.ParseCSeq(data)
		if c != nil {
			for _, v := range d.filter {
				if string(c) == v {
					return
				}
			}
		}
	}

	// if HPERM layer detected, comeback here again

	d.parser.DecodeLayers(data, &d.decodedLayers)
	//logp.Debug("layer", "\n%v", d.decodedLayers)
	foundGRELayer := false

	i, j := 0, 0
	for i := 0; i < len(d.decodedLayers); i++ {
		if d.decodedLayers[i] == layers.LayerTypeVXLAN {
			j = i
		}
	}

	for i = j; i < len(d.decodedLayers); i++ {
		switch d.decodedLayers[i] {
		case layers.LayerTypeGRE:
			if config.Cfg.Iface.WithErspan {
				erspanVer := d.gre.Payload[0] & 0xF0 >> 4
				if erspanVer == 1 && len(d.gre.Payload) > 8 {
					d.parser.DecodeLayers(d.gre.Payload[8:], &d.decodedLayers)
					if !foundGRELayer {
						i = 0
					}
					foundGRELayer = true
				} else if erspanVer == 2 && len(d.gre.Payload) > 12 {
					off := 12
					if d.gre.Payload[11]&1 == 1 && len(d.gre.Payload) > 20 {
						off = 20
					}
					d.parser.DecodeLayers(d.gre.Payload[off:], &d.decodedLayers)
					if !foundGRELayer {
						i = 0
					}
					foundGRELayer = true
				}
			} else {
				d.parser.DecodeLayers(d.gre.Payload, &d.decodedLayers)
				if !foundGRELayer {
					i = 0
				}
				foundGRELayer = true
			}

		case layers.LayerTypeIPv4:
			atomic.AddUint64(&d.ip4Count, 1)
			if d.ip4.Flags&layers.IPv4DontFragment != 0 || (d.ip4.Flags&layers.IPv4MoreFragments == 0 && d.ip4.FragOffset == 0) {
				d.processTransport(&d.decodedLayers, &d.udp, &d.tcp, &d.sctp, d.ip4.NetworkFlow(), ci, 0x02, uint8(d.ip4.Protocol), d.ip4.SrcIP, d.ip4.DstIP)
				break
			}

			ip4Len := d.ip4.Length
			ip4New, err := d.defragIP4(d.ip4, ci.Timestamp)
			if err != nil {
				logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, d.ip4.SrcIP, d.ip4.DstIP)
				return
			} else if ip4New == nil {
				atomic.AddUint64(&d.fragCount, 1)
				return
			}

			if ip4New.Length == ip4Len {
				d.processTransport(&d.decodedLayers, &d.udp, &d.tcp, &d.sctp, d.ip4.NetworkFlow(), ci, 0x02, uint8(d.ip4.Protocol), d.ip4.SrcIP, d.ip4.DstIP)
			} else {
				logp.Debug("defrag", "%d byte fragment layer: %s with payload:\n%s\n%d byte re-assembled payload:\n%s\n\n",
					ip4Len, d.decodedLayers, d.ip4.Payload, ip4New.Length, ip4New.Payload,
				)

				if ip4New.Protocol == layers.IPProtocolUDP {
					d.parserUDP.DecodeLayers(ip4New.Payload, &d.decodedLayers)
				} else if ip4New.Protocol == layers.IPProtocolTCP {
					d.parserTCP.DecodeLayers(ip4New.Payload, &d.decodedLayers)
				} else {
					logp.Warn("unsupported IPv4 fragment layer")
					return
				}
				d.processTransport(&d.decodedLayers, &d.udp, &d.tcp, &d.sctp, ip4New.NetworkFlow(), ci, 0x02, uint8(ip4New.Protocol), ip4New.SrcIP, ip4New.DstIP)
			}

		case layers.LayerTypeIPv6:
			atomic.AddUint64(&d.ip6Count, 1)
			if d.ip6.NextHeader != layers.IPProtocolIPv6Fragment {
				d.processTransport(&d.decodedLayers, &d.udp, &d.tcp, &d.sctp, d.ip6.NetworkFlow(), ci, 0x0a, uint8(d.ip6.NextHeader), d.ip6.SrcIP, d.ip6.DstIP)
				break
			}

			packet := gopacket.NewPacket(data, d.layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			if ip6frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ip6frag != nil {
				ip6New, err := d.defragIP6(d.ip6, *ip6frag, ci.Timestamp)
				if err != nil {
					logp.Warn("%v, srcIP: %s, dstIP: %s\n\n", err, d.ip6.SrcIP, d.ip6.DstIP)
					return
				} else if ip6New == nil {
					atomic.AddUint64(&d.fragCount, 1)
					return
				}

				logp.Debug("defrag", "%d byte fragment layer: %s with payload:\n%s\n%d byte re-assembled payload:\n%s\n\n",
					d.ip6.Length, d.decodedLayers, d.ip6.Payload, ip6New.Length, ip6New.Payload,
				)

				if ip6New.NextHeader == layers.IPProtocolUDP {
					d.parserUDP.DecodeLayers(ip6New.Payload, &d.decodedLayers)
				} else if ip6New.NextHeader == layers.IPProtocolTCP {
					d.parserTCP.DecodeLayers(ip6New.Payload, &d.decodedLayers)
				} else {
					logp.Warn("unsupported IPv6 fragment layer")
					return
				}
				d.processTransport(&d.decodedLayers, &d.udp, &d.tcp, &d.sctp, ip6New.NetworkFlow(), ci, 0x0a, uint8(ip6New.NextHeader), ip6New.SrcIP, ip6New.DstIP)
			}
		}
	}
}

func (d *Decoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, sctp *layers.SCTP, flow gopacket.Flow, ci *gopacket.CaptureInfo, IPVersion, IPProtocol uint8, sIP, dIP net.IP) {
	if config.Cfg.DiscardSrcIP != "" {
		for _, v := range d.filterSrcIP {
			if sIP.String() == v {
				return
			}
		}
	}

	pkt := &Packet{
		Version:  IPVersion,
		Protocol: IPProtocol,
		SrcIP:    sIP,
		DstIP:    dIP,
		Tsec:     uint32(ci.Timestamp.Unix()),
		Tmsec:    uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	for _, layerType := range *foundLayerTypes {
		switch layerType {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d.d1q.VLANIdentifier

		case layers.LayerTypeUDP:
			if len(udp.Payload) < 16 {
				logp.Warn("received too small %d byte UDP packet with payload %v", len(udp.Payload), udp.Payload)
				return
			}

			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
			pkt.Payload = udp.Payload
			atomic.AddUint64(&d.udpCount, 1)
			logp.Debug("payload", "UDP:\n%s", pkt)

			// HPERM layer check
			if pkt.SrcPort == 7932 || pkt.DstPort == 7932 {
				pkt := gopacket.NewPacket(pkt.Payload, d.hperm.LayerType(), gopacket.NoCopy)
				HPERML := pkt.Layer(d.hperm.LayerType())
				if HPERML != nil {
					logp.Info("Packet was successfully decoded with HPERM layer decoder.")
					HPERMpkt, _ := HPERML.(*ownlayers.HPERM)
					HPERMContent := HPERMpkt.LayerContents()
					HPERMPayload := HPERMpkt.LayerPayload()
					logp.Info("HPERM Content:", HPERMContent)
					logp.Info("Payload: ", HPERMPayload)
					// call again the process pkt to dissect the inner layers (aka the real pkt)
					d.Process(HPERMPayload, ci)
				}
			}

			if config.Cfg.Mode == "SIPLOG" {
				if udp.DstPort == 514 {
					pkt.ProtoType, pkt.CID = correlateLOG(udp.Payload)
					if pkt.ProtoType > 0 && pkt.CID != nil {
						PacketQueue <- pkt
					}
					return
				}
			}
			if config.Cfg.Mode != "SIP" {
				if (udp.Payload[0]&0xc0)>>6 == 2 {
					if (udp.Payload[1] == 200 || udp.Payload[1] == 201 || udp.Payload[1] == 207) && udp.SrcPort%2 != 0 && udp.DstPort%2 != 0 {
						pkt.Payload, pkt.CID = correlateRTCP(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, udp.Payload)
						if pkt.Payload != nil {
							pkt.ProtoType = 5
							atomic.AddUint64(&d.rtcpCount, 1)
							PacketQueue <- pkt
							return
						}
						atomic.AddUint64(&d.rtcpFailCount, 1)
						return
					} else if udp.SrcPort%2 == 0 && udp.DstPort%2 == 0 {
						if config.Cfg.Mode == "SIPRTP" {
							logp.Debug("rtp", "\n%v", protos.NewRTP(udp.Payload))
						}
						pkt.Payload = nil
						return
					}
				}
				extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)
			}

		case layers.LayerTypeTCP:
			pkt.SrcPort = uint16(tcp.SrcPort)
			pkt.DstPort = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload
			atomic.AddUint64(&d.tcpCount, 1)
			logp.Debug("payload", "TCP:\n%s", pkt)

			if config.Cfg.Reassembly {
				d.asm.AssembleWithTimestamp(flow, tcp, ci.Timestamp)
				return
			}
			extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)

		case layers.LayerTypeSCTP:
			pkt.SrcPort = uint16(sctp.SrcPort)
			pkt.DstPort = uint16(sctp.DstPort)
			switch sctp.Payload[8] {
			case 0: //DATA
				pkt.Payload = sctp.Payload[16:]
			case 64: //IDATA
				pkt.Payload = sctp.Payload[20:]
			}
			atomic.AddUint64(&d.sctpCount, 1)
			logp.Debug("payload", "SCTP:\n%s", pkt)

			extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)

		case layers.LayerTypeDNS:
			if config.Cfg.Mode == "SIPDNS" {
				pkt.ProtoType = 53
				pkt.Payload = protos.ParseDNS(&d.dns)
				atomic.AddUint64(&d.dnsCount, 1)
				PacketQueue <- pkt
				return
			}
		}
	}

	var cPos int
	if cPos = bytes.Index(pkt.Payload, []byte("CSeq")); cPos > -1 {
		pkt.ProtoType = 1
	} else if cPos = bytes.Index(pkt.Payload, []byte("Cseq")); cPos > -1 {
		pkt.ProtoType = 1
	}
	if cPos > 16 {
		if s := bytes.Index(pkt.Payload[:cPos], []byte("Sip0")); s > -1 {
			pkt.Payload = pkt.Payload[s+4:]
		}
	}

	if pkt.ProtoType > 0 && pkt.Payload != nil {
		PacketQueue <- pkt
	} else {
		atomic.AddUint64(&d.unknownCount, 1)
	}
}
