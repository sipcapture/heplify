package decoder

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/sipcapture/heplify/src/decoder/ip6defrag"
	"github.com/sipcapture/heplify/src/decoder/ownlayers"
)

// Packet represents a decoded network packet ready for HEP encoding
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
	TCPFlag   uint8
	IPTos     uint8
}

// Decoder handles packet decoding with support for encapsulations
type Decoder struct {
	layerType     gopacket.LayerType
	decodedLayers []gopacket.LayerType
	parser        *gopacket.DecodingLayerParser

	// Layer instances
	sll     layers.LinuxSLL
	d1q     layers.Dot1Q
	gre     layers.GRE
	eth     layers.Ethernet
	etherip layers.EtherIP
	vxl     ownlayers.VXLAN
	erspan  ownlayers.ERSPAN
	hperm   ownlayers.HPERM
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	sctp    layers.SCTP
	payload gopacket.Payload

	// IP defragmenters — always active (set to nil to disable via DisableIPDefrag).
	defrag4 *ip4defrag.IPv4Defragmenter
	defrag6 *ip6defrag.IPv6Defragmenter

	// TCPAssembler is optional. When set, all TCP packets are fed to it
	// instead of being returned from Decode (reassembled SIP arrives via callback).
	TCPAssembler *SIPAssembler
}

// NewDecoder creates a new decoder for the given link type
func NewDecoder(datalink layers.LinkType) *Decoder {
	var lt gopacket.LayerType
	switch datalink {
	case layers.LinkTypeEthernet:
		lt = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		lt = layers.LayerTypeLinuxSLL
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		// Raw IP link type: used by ipip (tunl0), sit (sit0) and similar tunnel interfaces.
		// The packet starts directly with an IP header — no Ethernet framing.
		lt = layers.LayerTypeIPv4
	default:
		lt = layers.LayerTypeEthernet
	}

	d := &Decoder{
		layerType:     lt,
		decodedLayers: make([]gopacket.LayerType, 0, 20),
		defrag4:       ip4defrag.NewIPv4Defragmenter(),
		defrag6:       ip6defrag.NewIPv6Defragmenter(),
	}

	dlp := gopacket.NewDecodingLayerParser(lt)
	dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	dlp.AddDecodingLayer(&d.sll)
	dlp.AddDecodingLayer(&d.d1q)
	dlp.AddDecodingLayer(&d.gre)
	dlp.AddDecodingLayer(&d.eth)
	dlp.AddDecodingLayer(&d.etherip)
	dlp.AddDecodingLayer(&d.vxl)
	dlp.AddDecodingLayer(&d.erspan)
	dlp.AddDecodingLayer(&d.hperm)
	dlp.AddDecodingLayer(&d.ip4)
	dlp.AddDecodingLayer(&d.ip6)
	dlp.AddDecodingLayer(&d.sctp)
	dlp.AddDecodingLayer(&d.udp)
	dlp.AddDecodingLayer(&d.tcp)
	dlp.AddDecodingLayer(&d.payload)
	dlp.IgnoreUnsupported = true

	d.parser = dlp

	return d
}

// Decode decodes a packet and returns a Packet struct
func (d *Decoder) Decode(data []byte, ci gopacket.CaptureInfo) (*Packet, error) {
	d.decodedLayers = d.decodedLayers[:0]

	if err := d.parser.DecodeLayers(data, &d.decodedLayers); err != nil {
		_ = err // unsupported layer types are intentionally ignored
	}

	pkt := &Packet{
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	var foundIP, foundTransport bool
	var ip4Fragment, ip6Fragment bool

	for _, layerType := range d.decodedLayers {
		switch layerType {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d.d1q.VLANIdentifier

		case layers.LayerTypeIPv4:
			pkt.Version = 0x02
			pkt.SrcIP = d.ip4.SrcIP
			pkt.DstIP = d.ip4.DstIP
			pkt.IPTos = d.ip4.TOS
			foundIP = true
			if d.ip4.Flags&layers.IPv4MoreFragments != 0 || d.ip4.FragOffset > 0 {
				ip4Fragment = true
			}

		case layers.LayerTypeIPv6:
			pkt.Version = 0x0a
			pkt.SrcIP = d.ip6.SrcIP
			pkt.DstIP = d.ip6.DstIP
			foundIP = true
			if d.ip6.NextHeader == layers.IPProtocolIPv6Fragment {
				ip6Fragment = true
			}

		case layers.LayerTypeUDP:
			pkt.Protocol = 0x11
			pkt.SrcPort = uint16(d.udp.SrcPort)
			pkt.DstPort = uint16(d.udp.DstPort)
			pkt.Payload = d.udp.Payload
			foundTransport = true

		case layers.LayerTypeTCP:
			pkt.Protocol = 0x06
			pkt.SrcPort = uint16(d.tcp.SrcPort)
			pkt.DstPort = uint16(d.tcp.DstPort)
			pkt.Payload = d.tcp.Payload
			pkt.TCPFlag = boolToUint8(d.tcp.SYN)<<1 | boolToUint8(d.tcp.FIN) | boolToUint8(d.tcp.RST)<<2 | boolToUint8(d.tcp.PSH)<<3 | boolToUint8(d.tcp.ACK)<<4
			foundTransport = true

		case layers.LayerTypeSCTP:
			pkt.Protocol = 0x84
			pkt.SrcPort = uint16(d.sctp.SrcPort)
			pkt.DstPort = uint16(d.sctp.DstPort)
			pkt.Payload = d.sctp.Payload
			foundTransport = true

		case layers.LayerTypeVXLAN:
			if len(d.vxl.Payload) > 0 {
				if innerPkt := d.decodeInnerPacket(d.vxl.Payload, ci); innerPkt != nil {
					return innerPkt, nil
				}
			}

		case ownlayers.LayerTypeERSPAN:
			if d.erspan.VLan > 0 {
				pkt.Vlan = d.erspan.VLan
			}
			if len(d.erspan.Payload) > 0 {
				if innerPkt := d.decodeInnerPacket(d.erspan.Payload, ci); innerPkt != nil {
					return innerPkt, nil
				}
			}

		case layers.LayerTypeGRE:
			if d.gre.Protocol == layers.EthernetTypeTransparentEthernetBridging {
				if len(d.gre.Payload) >= 8 {
					if innerPkt := d.decodeInnerPacket(d.gre.Payload[8:], ci); innerPkt != nil {
						return innerPkt, nil
					}
				}
			}
		}
	}

	// IPv4 defragmentation
	if ip4Fragment && d.defrag4 != nil {
		// Pass a copy: ip4defrag stores the pointer; d.ip4 is reused on every Decode().
		ip4Copy := d.ip4
		ip4New, err := d.defrag4.DefragIPv4WithTimestamp(&ip4Copy, ci.Timestamp)
		if err != nil || ip4New == nil {
			return nil, nil // fragment buffered, wait for more
		}
		// Reassembled — decode transport from the assembled payload.
		proto, sp, dp, flags, payload, ok := decodeTransport(ip4New.Protocol, ip4New.Payload)
		if !ok {
			return nil, nil
		}
		pkt.Protocol = proto
		pkt.SrcPort = sp
		pkt.DstPort = dp
		pkt.TCPFlag = flags
		pkt.Payload = payload
		foundTransport = true
	}

	// IPv6 defragmentation
	if ip6Fragment && d.defrag6 != nil {
		fragData := d.ip6.Payload
		if len(fragData) < 8 {
			return nil, nil
		}
		frag := layers.IPv6Fragment{
			BaseLayer:      layers.BaseLayer{Contents: fragData[:8], Payload: fragData[8:]},
			NextHeader:     layers.IPProtocol(fragData[0]),
			Reserved1:      fragData[1],
			FragmentOffset: binary.BigEndian.Uint16(fragData[2:4]) >> 3,
			Reserved2:      fragData[3] & 0x6 >> 1,
			MoreFragments:  fragData[3]&0x1 != 0,
			Identification: binary.BigEndian.Uint32(fragData[4:8]),
		}
		// Pass a copy of the IPv6 header too.
		ip6Copy := d.ip6
		ip6New, err := d.defrag6.DefragIPv6WithTimestamp(&ip6Copy, &frag, ci.Timestamp)
		if err != nil || ip6New == nil {
			return nil, nil // fragment buffered, wait for more
		}
		proto, sp, dp, flags, payload, ok := decodeTransport(ip6New.NextHeader, ip6New.Payload)
		if !ok {
			return nil, nil
		}
		pkt.Protocol = proto
		pkt.SrcPort = sp
		pkt.DstPort = dp
		pkt.TCPFlag = flags
		pkt.Payload = payload
		foundTransport = true
	}

	if !foundIP || !foundTransport {
		return nil, nil
	}

	// TCP reassembly: feed the segment to the assembler and let the callback
	// deliver complete SIP messages. Do not return the raw segment.
	if pkt.Protocol == 0x06 && d.TCPAssembler != nil {
		var netFlow gopacket.Flow
		if pkt.Version == 0x02 {
			netFlow = d.ip4.NetworkFlow()
		} else {
			netFlow = d.ip6.NetworkFlow()
		}
		d.TCPAssembler.Feed(netFlow, &d.tcp, ci.Timestamp)
		return nil, nil
	}

	return pkt, nil
}

// decodeInnerPacket decodes an inner Ethernet frame (e.g., from VXLAN or ERSPAN)
func (d *Decoder) decodeInnerPacket(data []byte, ci gopacket.CaptureInfo) *Packet {
	// Create a new parser for the inner frame starting with Ethernet
	var eth layers.Ethernet
	var d1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &d1q, &ip4, &ip6, &tcp, &udp, &payload,
	)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, 10)
	if err := parser.DecodeLayers(data, &decoded); err != nil {
		_ = err // unsupported layer types are intentionally ignored
	}

	pkt := &Packet{
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	var foundIP, foundTransport bool

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeDot1Q:
			pkt.Vlan = d1q.VLANIdentifier
		case layers.LayerTypeIPv4:
			pkt.Version = 0x02
			pkt.SrcIP = ip4.SrcIP
			pkt.DstIP = ip4.DstIP
			pkt.IPTos = ip4.TOS
			foundIP = true
		case layers.LayerTypeIPv6:
			pkt.Version = 0x0a
			pkt.SrcIP = ip6.SrcIP
			pkt.DstIP = ip6.DstIP
			foundIP = true
		case layers.LayerTypeUDP:
			pkt.Protocol = 0x11
			pkt.SrcPort = uint16(udp.SrcPort)
			pkt.DstPort = uint16(udp.DstPort)
			pkt.Payload = udp.Payload
			foundTransport = true
		case layers.LayerTypeTCP:
			pkt.Protocol = 0x06
			pkt.SrcPort = uint16(tcp.SrcPort)
			pkt.DstPort = uint16(tcp.DstPort)
			pkt.Payload = tcp.Payload
			foundTransport = true
		}
	}

	if !foundIP || !foundTransport {
		return nil
	}

	return pkt
}

// GetSrcIP returns source IP as string
func (p *Packet) GetSrcIP() string {
	return p.SrcIP.String()
}

// GetDstIP returns destination IP as string
func (p *Packet) GetDstIP() string {
	return p.DstIP.String()
}

// GetSrcPort returns source port
func (p *Packet) GetSrcPort() uint16 {
	return p.SrcPort
}

// GetDstPort returns destination port
func (p *Packet) GetDstPort() uint16 {
	return p.DstPort
}

// GetTsec returns timestamp seconds
func (p *Packet) GetTsec() uint32 {
	return p.Tsec
}

// GetTmsec returns timestamp microseconds
func (p *Packet) GetTmsec() uint32 {
	return p.Tmsec
}

// GetProtoType returns protocol type
func (p *Packet) GetProtoType() uint32 {
	return uint32(p.ProtoType)
}

// GetPayload returns payload as string
func (p *Packet) GetPayload() string {
	return string(p.Payload)
}

// DisableDefrag disables IP defragmentation for both IPv4 and IPv6.
func (d *Decoder) DisableDefrag() {
	d.defrag4 = nil
	d.defrag6 = nil
}

// boolToUint8 converts bool to uint8 (0 or 1)
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// decodeTransport decodes a UDP or TCP header from payload reassembled after IP defragmentation.
// Returns (ipProto, srcPort, dstPort, tcpFlags, appPayload, ok).
func decodeTransport(proto layers.IPProtocol, payload []byte) (ipProto byte, srcPort, dstPort uint16, tcpFlags uint8, appPayload []byte, ok bool) {
	switch proto {
	case layers.IPProtocolUDP:
		var udp layers.UDP
		if err := udp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		return 0x11, uint16(udp.SrcPort), uint16(udp.DstPort), 0, udp.Payload, true

	case layers.IPProtocolTCP:
		var tcp layers.TCP
		if err := tcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		flags := boolToUint8(tcp.SYN)<<1 | boolToUint8(tcp.FIN) | boolToUint8(tcp.RST)<<2 | boolToUint8(tcp.PSH)<<3 | boolToUint8(tcp.ACK)<<4
		return 0x06, uint16(tcp.SrcPort), uint16(tcp.DstPort), flags, tcp.Payload, true

	case layers.IPProtocolSCTP:
		var sctp layers.SCTP
		if err := sctp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		return 0x84, uint16(sctp.SrcPort), uint16(sctp.DstPort), 0, sctp.Payload, true
	}
	return
}
