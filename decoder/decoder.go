package decoder

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"
	"time"

	"github.com/allegro/bigcache"
	"github.com/cespare/xxhash"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hashicorp/golang-lru"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/ip4defrag"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

type Decoder struct {
	Host         string
	defragger    *ip4defrag.IPv4Defragmenter
	fragCount    int
	dupCount     int
	ip4Count     int
	udpCount     int
	tcpCount     int
	dnsCount     int
	unknownCount int
	IPFlow       gopacket.Flow
	UDPFlow      gopacket.Flow
	lru          *lru.ARCCache
	bigcache     *bigcache.BigCache
	hash         hash.Hash64
}

type Packet struct {
	Host          string
	Tsec          uint32
	Tmsec         uint32
	Version       uint8
	Protocol      uint8
	Srcip         uint32
	Dstip         uint32
	Sport         uint16
	Dport         uint16
	CorrelationID []byte
	Payload       []byte
}

func NewDecoder() *Decoder {
	host, err := os.Hostname()
	if err != nil {
		host = "sniffer"
	}

	la, err := lru.NewARC(8192)
	if err != nil {
		logp.Err("lru %v", err)
	}

	xh := xxhash.New()

	bConf := bigcache.Config{
		// number of shards (must be a power of 2)
		Shards: 1024,
		// time after which entry can be evicted
		LifeWindow: 10 * time.Minute,
		// rps * lifeWindow, used only in initial memory allocation
		MaxEntriesInWindow: 1000 * 180 * 60,
		// max entry size in bytes, used only in initial memory allocation
		MaxEntrySize: 384,
		// prints information about additional memory allocation
		Verbose: true,
		// cache will not allocate more memory than this limit, value in MB
		// if value is reached then the oldest entries can be overridden for the new ones
		// 0 value means no size limit
		HardMaxCacheSize: 1024,
		// callback fired when the oldest entry is removed because of its
		// expiration time or no space left for the new entry. Default value is nil which
		// means no callback and it prevents from unwrapping the oldest entry.
		OnRemove: nil,
	}

	bc, err := bigcache.NewBigCache(bConf)
	if err != nil {
		logp.Err("bigcache %v", err)
	}

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
		lru:          la,
		hash:         xh,
		bigcache:     bc,
	}
	go d.flushFrag()
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
				d.dupCount++
				return nil, nil
			}
		}

		d.IPFlow = ip4.NetworkFlow()
		d.ip4Count++

		pkt.Version = ip4.Version
		pkt.Protocol = uint8(ip4.Protocol)
		pkt.Srcip = ip2int(ip4.SrcIP)
		pkt.Dstip = ip2int(ip4.DstIP)

		ip4New, err := d.defragger.DefragIPv4(ip4)
		if err != nil {
			logp.Warn("Error while de-fragmenting", err)
			return nil, nil
		} else if ip4New == nil {
			d.fragCount++
			return nil, nil
		}

		if ip4New.Length != ip4Len {
			logp.Debug("decoder", "Decoding fragmented packet layers:\n%v\nFragmented packet payload:\n%v\nRe-assembled packet payload:\n%v\nRe-assembled packet length:\n%v\n\n",
				packet, string(packet.ApplicationLayer().Payload()), string(ip4New.Payload[8:]), ip4New.Length,
			)

			pkt.Version = ip4New.Version
			pkt.Protocol = uint8(ip4New.Protocol)
			pkt.Srcip = ip2int(ip4New.SrcIP)
			pkt.Dstip = ip2int(ip4New.DstIP)

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

		d.UDPFlow = udp.TransportFlow()
		d.udpCount++

		pkt.Sport = uint16(udp.SrcPort)
		pkt.Dport = uint16(udp.DstPort)
		pkt.Payload = udp.Payload

		if config.Cfg.Mode == "SIPRTCP" {
			d.cacheSDPIPPort(udp.Payload)
			if (udp.Payload[0]&0xc0)>>6 == 2 && (udp.Payload[1] == 200 || udp.Payload[1] == 201) {
				pkt.Payload, pkt.CorrelationID = d.correlateRTCP(udp.Payload)
			}
		}

	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, nil
		}
		d.tcpCount++
		pkt.Sport = uint16(tcp.SrcPort)
		pkt.Dport = uint16(tcp.DstPort)
		pkt.Payload = tcp.Payload

		if config.Cfg.Mode == "SIPRTCP" {
			d.cacheSDPIPPort(tcp.Payload)
		}
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, ok := dnsLayer.(*layers.DNS)
		if !ok {
			return nil, nil
		}
		d.dnsCount++
		pkt.Payload = protos.NewDNS(dns)
	}

	// TODO: add more layers like DHCP, NTP

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if config.Cfg.Mode == "TLS" {
			pkt.Payload = protos.NewTLS(appLayer.Payload())
		} else {
			logp.Debug("decoder", "Captured payload:\n%v\n", string(appLayer.Payload()))
		}
	}

	if pkt.Payload != nil {
		return pkt, nil
	}

	d.unknownCount++
	return nil, nil
}

func (d *Decoder) cacheSDPIPPort(payload []byte) error {
	var SDPIP, RTCPPort string
	var callID []byte

	if posSDPIP, posSDPPort := bytes.Index(payload, []byte("c=IN IP4 ")), bytes.Index(payload, []byte("m=audio ")); posSDPIP >= 0 && posSDPPort >= 0 {
		restIP := payload[posSDPIP:]
		if posRestIP := bytes.Index(restIP, []byte("\r\n")); posRestIP >= 0 {
			SDPIP = string(restIP[len("c=IN IP4 "):bytes.Index(restIP, []byte("\r\n"))])
		} else {
			return errors.New("Couldn't find end of SDP IP")
		}

		restPort := payload[posSDPPort:]
		if posRestPort := bytes.Index(restIP, []byte(" RTP")); posRestPort >= 0 {
			SDPPort, err := strconv.Atoi(string(restPort[len("m=audio "):bytes.Index(restPort, []byte(" RTP"))]))
			if err != nil {
				return err
			}
			RTCPPort = strconv.Itoa(SDPPort + 1)
		} else {
			return errors.New("Couldn't find end of SDP Port")
		}

		if posCallID := bytes.Index(payload, []byte("Call-ID: ")); posCallID >= 0 {
			restCallID := payload[posCallID:]
			if posRestCallID := bytes.Index(restIP, []byte("\r\n")); posRestCallID >= 0 {
				callID = restCallID[len("Call-ID: "):bytes.Index(restCallID, []byte("\r\n"))]
			} else {
				return errors.New("Couldn't find end of Call-ID")
			}
		} else if posID := bytes.Index(payload, []byte("i: ")); posID >= 0 {
			restID := payload[posID:]
			if posRestID := bytes.Index(restIP, []byte("\r\n")); posRestID >= 0 {
				callID = restID[len("i: "):bytes.Index(restID, []byte("\r\n"))]
			} else {
				return errors.New("Couldn't find end of Call-ID")
			}
		}
		d.bigcache.Set(SDPIP+RTCPPort, callID)
	}
	return nil
}

func (d *Decoder) correlateRTCP(payload []byte) ([]byte, []byte) {
	jsonRTCP, err := protos.ParseRTCP(payload)
	if err != nil {
		logp.Warn("%v", err)
		return nil, nil
	}

	corrID, err := d.bigcache.Get(d.IPFlow.Src().String() + d.UDPFlow.Src().String())
	if err != nil {
		logp.Warn("%v", err)
		return nil, nil
	}

	fmt.Println(string(jsonRTCP))
	return jsonRTCP, corrID
}
