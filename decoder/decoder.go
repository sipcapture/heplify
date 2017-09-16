package decoder

import (
	"encoding/json"
	"hash"
	"os"

	"github.com/cespare/xxhash"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hashicorp/golang-lru"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
	"github.com/negbie/tlsx"
	//"github.com/negbie/sippar"
	//"github.com/negbie/siprocket"
)

type Decoder struct {
	Host      string
	defragger *ip4defrag.IPv4Defragmenter
	mfc       int
	lru       *lru.ARCCache
	hash      hash.Hash64
}

type Packet struct {
	Host          string
	Tsec          uint32
	Tmsec         uint32
	Srcip         uint32
	Dstip         uint32
	Sport         uint16
	Dport         uint16
	CorrelationID []byte
	Payload       []byte
	//sipMsg        *sipparser.SipMsg
	//SipMsg        siprocket.SipMsg
	//SipHeader map[string][]string
}

func NewDecoder() *Decoder {

	host, err := os.Hostname()
	if err != nil {
		host = "sniffer"
	}
	l, err := lru.NewARC(8192)
	if err != nil {
		logp.Err("lru %v", err)
	}
	h := xxhash.New()
	d := &Decoder{Host: host, defragger: ip4defrag.NewIPv4Defragmenter(), mfc: 0, lru: l, hash: h}
	go d.fragFlush()
	return d
}

func (d *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (*Packet, error) {
	pkt := &Packet{
		Host:  d.Host,
		Tsec:  uint32(ci.Timestamp.Unix()),
		Tmsec: uint32(ci.Timestamp.Nanosecond() / 1000),
	}

	/* 	if config.Cfg.Mode == "SIP" {
		pkt.SipMsg = siprocket.Parse(data)
		pkt.sipMsg = sipparser.ParseMsg(string(data))
		return pkt, nil
	} */

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	logp.Debug("decoder", "Captured packet layers:\n%v\n", packet)

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4, ok := ipLayer.(*layers.IPv4)
		ip4Len := ip4.Length

		if !ok {
			return nil, nil
		}

		if config.Cfg.Dedup {
			d.hash.Write(ip4.Payload)
			//key := fastHash(ip4.Payload)
			key := d.hash.Sum64()
			d.hash.Reset()
			_, dup := d.lru.Get(key)
			d.lru.Add(key, nil)
			if dup == true {
				return nil, nil
			}
		}

		pkt.Srcip = ip2int(ip4.SrcIP)
		pkt.Dstip = ip2int(ip4.DstIP)

		ip4New, err := d.defragger.DefragIPv4(ip4)
		if err != nil {
			logp.Err("Error while de-fragmenting", err)
			return nil, err
		} else if ip4New == nil {
			//packet fragment, we don't have whole packet yet. Send it anyway and overwrite it later
			return nil, nil
		}

		if ip4New.Length != ip4Len {
			d.mfc++

			if d.mfc%128 == 0 {
				logp.Warn("Defragmentated packet counter: %d", d.mfc)
			}
			logp.Info("Decoding fragmented packet layers:\n%v\nFragmented packet payload:\n%v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
				packet, string(packet.ApplicationLayer().Payload()), string(ip4New.Payload[8:]), ip4New.Length,
			)

			pkt.Srcip = ip2int(ip4New.SrcIP)
			pkt.Dstip = ip2int(ip4New.DstIP)

			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := ip4New.NextLayerType()
			nextDecoder.Decode(ip4New.Payload, pb)
		}
		// TODO: generate a more meaningful CorrelationID
		if config.Cfg.Mode == "DNS" || config.Cfg.Mode == "LOG" || config.Cfg.Mode == "TLS" {
			pkt.CorrelationID = []byte(config.Cfg.Mode)
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(tcp.SrcPort)
		pkt.Dport = uint16(tcp.DstPort)
		pkt.Payload = tcp.Payload
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil, nil
		}
		pkt.Sport = uint16(udp.SrcPort)
		pkt.Dport = uint16(udp.DstPort)
		pkt.Payload = udp.Payload
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, ok := dnsLayer.(*layers.DNS)
		if !ok {
			return nil, nil
		}

		jsonDNS, err := json.Marshal(protos.NewDNS(dns))
		if err != nil {
			logp.Warn("jsonDNS marshal", err)
			return nil, err
		}
		pkt.Payload = jsonDNS
	}

	// TODO: add more layers like DHCP, NTP
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		logp.Debug("decoder", "Captured payload:\n%v\n", string(appLayer.Payload()))

		// TODO: move this to protos tls
		if config.Cfg.Mode == "TLS" {
			if pkt.Dport == 443 || pkt.Sport == 443 {
				var hello = tlsx.ClientHello{}
				err := hello.Unmarshall(appLayer.Payload())

				switch err {
				case nil:
					logp.Debug("Captured payload:\n %v\n", hello.String())
					pkt.Payload = []byte(hello.String())
				case tlsx.ErrHandshakeWrongType:
					return nil, nil
				default:
					return nil, nil
				}
			}
		}

		/* 	if config.Cfg.Mode == "SIP" {
			sipl := gopacket.NewPacket(appLayer.Payload(), ownlayers.LayerTypeSIP, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			_, ok := sipl.Layers()[0].(*ownlayers.SIP)
			if !ok {
				return nil, nil
			}
		} */
	}

	if pkt.Payload != nil {
		return pkt, nil
	}
	return nil, nil
}
