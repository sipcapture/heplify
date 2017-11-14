package decoder

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/coocood/freecache"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

type Decoder struct {
	Host          string
	defragger     *ip4defrag.IPv4Defragmenter
	fragCount     int
	dupCount      int
	dnsCount      int
	ip4Count      int
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
	HEPType       byte
	Tsec          uint32
	Tmsec         uint32
	Version       uint8
	Protocol      uint8
	SrcIP         uint32
	DstIP         uint32
	SrcPort       uint16
	DstPort       uint16
	CorrelationID []byte
	Payload       []byte
}

func NewDecoder() *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = "sniffer"
	}

	cSIP := freecache.NewCache(20 * 1024 * 1024)  // 20MB
	cSDP := freecache.NewCache(20 * 1024 * 1024)  // 20MB
	cRTCP := freecache.NewCache(60 * 1024 * 1024) // 60MB
	debug.SetGCPercent(20)

	d := &Decoder{
		Host:         host,
		defragger:    ip4defrag.NewIPv4Defragmenter(),
		fragCount:    0,
		dupCount:     0,
		ip4Count:     0,
		udpCount:     0,
		tcpCount:     0,
		dnsCount:     0,
		unknownCount: 0,
		SIPCache:     cSIP,
		SDPCache:     cSDP,
		RTCPCache:    cRTCP,
	}
	go d.flushFragments()
	go d.printStats()
	return d
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	logp.Debug("layers", "\n%v", packet)

	if config.Cfg.Dedup {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			logp.Debug("payload", "\n%v", string(appLayer.Payload()))
			_, err := d.SIPCache.Get(appLayer.Payload())
			if err == nil {
				d.dupCount++
				return nil, nil
			}
			err = d.SIPCache.Set(appLayer.Payload(), nil, 2)
			if err != nil {
				logp.Warn("%v", err)
			}
		}
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4, ok := ipLayer.(*layers.IPv4)
		ip4Len := ip4.Length
		if !ok {
			return nil, nil
		}

		pkt.Version = ip4.Version
		pkt.Protocol = uint8(ip4.Protocol)
		pkt.SrcIP = ip2int(ip4.SrcIP)
		pkt.DstIP = ip2int(ip4.DstIP)
		d.ip4Count++

		if config.Cfg.Mode == "SIP" || config.Cfg.Mode == "SIPRTCP" {
			pkt.HEPType = 1
		}

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

			pkt.Version = ip4New.Version
			pkt.Protocol = uint8(ip4New.Protocol)
			pkt.SrcIP = ip2int(ip4New.SrcIP)
			pkt.DstIP = ip2int(ip4New.DstIP)

			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				logp.Critical("Not a PacketBuilder")
			}
			nextDecoder := ip4New.NextLayerType()
			nextDecoder.Decode(ip4New.Payload, pb)
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil, nil
		}

		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.Payload = udp.Payload
		d.udpCount++

		d.FlowSrcPort = fmt.Sprintf("%d", udp.SrcPort)
		d.FlowDstPort = fmt.Sprintf("%d", udp.DstPort)

		if config.Cfg.Mode == "SIPRTCP" {
			d.cacheSDPIPPort(udp.Payload)
			if (udp.Payload[0]&0xc0)>>6 == 2 && udp.SrcPort%2 != 0 && udp.DstPort%2 != 0 && (udp.Payload[1] == 200 || udp.Payload[1] == 201) {
				pkt.Payload, pkt.CorrelationID, pkt.HEPType = d.correlateRTCP(udp.Payload)
				if pkt.Payload == nil {
					d.rtcpFailCount++
				} else {
					d.rtcpCount++
				}
			}
		}

	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, nil
		}

		pkt.SrcPort = uint16(tcp.SrcPort)
		pkt.DstPort = uint16(tcp.DstPort)
		pkt.Payload = tcp.Payload
		d.tcpCount++

		if config.Cfg.Mode == "SIPRTCP" {
			d.cacheSDPIPPort(tcp.Payload)
		}
	}

	// TODO: add more layers like DHCP, NTP
	if config.Cfg.Mode == "DNS" {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, ok := dnsLayer.(*layers.DNS)
			if !ok {
				return nil, nil
			}
			d.dnsCount++
			pkt.Payload = protos.ParseDNS(dns)
			pkt.HEPType = 100
		}
	}

	if config.Cfg.Mode == "TLS" {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			pkt.Payload = protos.NewTLS(appLayer.Payload())
			pkt.HEPType = 100

		}
	}

	if pkt.Payload != nil {
		return pkt, nil
	}

	d.unknownCount++
	return nil, nil
}
