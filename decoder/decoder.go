package decoder

import (
	"bytes"
	"container/list"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/segmentio/encoding/json"

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

var (
	PacketQueue = make(chan *Packet, 20000)
	scriptCache = fastcache.New(32 * 1024 * 1024)
)

type CachePayload struct {
	SrcIP         net.IP `json:"src_ip" default:""`
	SrcPort       uint16 `json:"src_port"`
	DstIP         net.IP `json:"dst_ip"`
	DstPort       uint16 `json:"dst_port"`
	AckNumber     uint32 `json:"ack_number"`
	SeqNumber     uint32 `json:"seq_number"`
	NextSeqNumber uint32 `json:"next_seq_number"`
	RemainLength  int    `json:"remain_length" default:"-1"`
	FrameCount    int    `json:"frame_count" default:"0"`
	Payload       []byte `json:"payload"`
}

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
	etherip       layers.EtherIP
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
	filterIP      []string
	filterSrcIP   []string
	filterDstIP   []string
	cachePayload  *freecache.Cache
	lastStatTime  time.Time
	stats
}

type stats struct {
	fragCount     uint64
	dupCount      uint64
	dnsCount      uint64
	ip4Count      uint64
	ip6Count      uint64
	rtcpCount     uint64
	rtcpFailCount uint64
	tcpCount      uint64
	hepCount      uint64
	sctpCount     uint64
	udpCount      uint64
	unknownCount  uint64
	_             uint32
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
	Mos       uint16
	TCPFlag   uint8
	IPTos     uint8
}

// HEP chuncks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
	NodeName  = 19 // Chunk 0x0013 NodeName
)

// HEP represents HEP packet
type HEP struct {
	Version     uint32 `protobuf:"varint,1,req,name=Version" json:"Version"`
	Protocol    uint32 `protobuf:"varint,2,req,name=Protocol" json:"Protocol"`
	SrcIP       string `protobuf:"bytes,3,req,name=SrcIP" json:"SrcIP"`
	DstIP       string `protobuf:"bytes,4,req,name=DstIP" json:"DstIP"`
	SrcPort     uint32 `protobuf:"varint,5,req,name=SrcPort" json:"SrcPort"`
	DstPort     uint32 `protobuf:"varint,6,req,name=DstPort" json:"DstPort"`
	Tsec        uint32 `protobuf:"varint,7,req,name=Tsec" json:"Tsec"`
	Tmsec       uint32 `protobuf:"varint,8,req,name=Tmsec" json:"Tmsec"`
	ProtoType   uint32 `protobuf:"varint,9,req,name=ProtoType" json:"ProtoType"`
	NodeID      uint32 `protobuf:"varint,10,req,name=NodeID" json:"NodeID"`
	NodePW      string `protobuf:"bytes,11,req,name=NodePW" json:"NodePW"`
	Payload     string `protobuf:"bytes,12,req,name=Payload" json:"Payload"`
	CID         string `protobuf:"bytes,13,req,name=CID" json:"CID"`
	Vlan        uint32 `protobuf:"varint,14,req,name=Vlan" json:"Vlan"`
	ProtoString string
	Timestamp   time.Time
	SIP         string
	NodeName    string
	TargetName  string
	SID         string
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
	dlp.AddDecodingLayer(&d.etherip)
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
	d.filterIP = strings.Split(config.Cfg.DiscardIP, ",")
	d.filterSrcIP = strings.Split(config.Cfg.DiscardSrcIP, ",")
	d.filterDstIP = strings.Split(config.Cfg.DiscardDstIP, ",")

	d.cachePayload = freecache.NewCache(1024 * 1024 * 1024)
	d.lastStatTime = time.Now()
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

var SIP_REQUEST_METHOD = []string{
	"INVITE",
	"REGISTER",
	"ACK",
	"BYE",
	"CANCEL",
	"OPTIONS",
	"PUBLISH",
	"INFO",
	"PRACK",
	"SUBSCRIBE",
	"NOTIFY",
	"UPDATE",
	"MESSAGE",
	"REFER",
}

var SIP_RESPONSE_TEXT = []string{
	"OK",
	"TRYING",
	"GIVING A TRY",
	"CANCEL",
	"CANCELING",
	"RINGING",
	"REQUEST TERMINATED",
	"SESSION PROGRESS",
	"UNAUTHORIZED",
	"BUSY HERE",
	"TEMPORARILY UNAVAILABLE",
	"CALL DOES NOT EXIST",
	"LOOP DETECTED",
	"ADDRESS INCOMPLETE",
	"NOT ACCEPTABLE HERE",
	"INTERNAL SERVER ERROR",
	"DECLINE",
	"DOES NOT EXIST ANYWHERE",
	"REG NOT FOUND",
	"NOT ACCEPTABLE",
	"NOT FOUND",
	"CALL LEG/TRANSACTION DOES NOT EXIST",
	"UNHANDLED BY DIALOG USAGES",
	"ACCEPTED",
	"REQUEST TIMEOUT",
	"BAD REQUEST",
	"FORBIDDEN",
	"INVALID CSEQ",
	"REQUEST CANCELLED",
	"DEFAULT STATUS MESSAGE",
	"OVERLAPPING REQUESTS",
	"REQUEST PENDING",
	"PAYMENT REQUIRED",
	"UNSUPPORTED MEDIA TYPE",
	"GATEWAY TIME-OUT",
	"MOVED TEMPORARILY",
	"CALL IS BEING TERMINATED",
	"TOO MANY HOPS",
	"BAD GATEWAY",
	"NOT IMPLEMENTED",
	"SESSION TERMINATED",
	"CALL/TRANSACTION DOES NOT EXIST",
	"PRECONDITION FAILURE",
	"BAD SESSION DESCRIPTION",
	"NEXT SERVICE  TEMPORARILY UNAVAILABLE",
}

func startLineRequest(val string) int {
	upperVal := strings.ToUpper(val)
	indexEnd := strings.Index(upperVal, " SIP/2.0")
	if indexEnd <= 0 {
		return -1
	}

	if indexEnd != len(upperVal)-len(" SIP/2.0") {
		return -1
	}

	indexStart := -1
	for index := range SIP_REQUEST_METHOD {
		indexStart = strings.Index(upperVal, SIP_REQUEST_METHOD[index])
		if indexStart >= 0 {
			break
		}
	}

	if indexStart < 0 {
		return -1
	}

	upperVal = upperVal[indexStart:]
	parts := strings.SplitN(upperVal, " ", 3)
	if len(parts) != 3 {
		return -1
	}

	for index := range parts {
		if len(parts[index]) <= 0 {
			return -1
		}
	}

	if len(parts[1]) < 8 || !strings.Contains(parts[1], "SIP:") {
		return -1
	}

	if !strings.EqualFold(parts[2], "SIP/2.0") {
		return -1
	}

	for index := range SIP_REQUEST_METHOD {
		if strings.EqualFold(parts[0], SIP_REQUEST_METHOD[index]) {
			return indexStart
		}
	}

	return -1
}

func startLineResponse(val string) int {
	upperVal := strings.ToUpper(val)
	indexStart := strings.Index(upperVal, "SIP/2.0 ")
	if indexStart < 0 {
		return -1
	}

	upperVal = upperVal[indexStart:]

	parts := strings.SplitN(upperVal, " ", 3)
	if len(parts) != 3 {
		return -1
	}

	if !strings.EqualFold(parts[0], "SIP/2.0") {
		return -1
	}

	responseCode, err := strconv.Atoi(parts[1])
	if err != nil || responseCode <= 0 {
		return -1
	}

	if len(strings.TrimSpace(parts[2])) <= 0 {
		return indexStart
	}

	for index := range SIP_RESPONSE_TEXT {
		if strings.EqualFold(parts[2], SIP_RESPONSE_TEXT[index]) {
			return indexStart
		}
	}

	logp.Warn("startLineResponse missed response text val = %s", val)
	return indexStart
}

func (d *Decoder) addCachePayload(cachePayload *CachePayload) (result bool) {
	if len(cachePayload.Payload) <= 0 {
		return true
	}

	cacheData, _ := json.Marshal(cachePayload)
	cacheKeyBuffer := bytes.Buffer{}
	cacheKeyBuffer.WriteString(cachePayload.SrcIP.String())
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.SrcPort), 10))
	cacheKeyBuffer.WriteString(cachePayload.DstIP.String())
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.DstPort), 10))
	//cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.AckNumber), 10))
	cacheKeyBuffer.WriteString("last")
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.NextSeqNumber), 10))
	d.cachePayload.Set(cacheKeyBuffer.Bytes(), cacheData, 30)

	cacheKeyBuffer.Reset()
	cacheKeyBuffer.WriteString(cachePayload.SrcIP.String())
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.SrcPort), 10))
	cacheKeyBuffer.WriteString(cachePayload.DstIP.String())
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.DstPort), 10))
	//cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.AckNumber), 10))
	cacheKeyBuffer.WriteString("next")
	cacheKeyBuffer.WriteString(strconv.FormatUint(uint64(cachePayload.SeqNumber), 10))
	err := d.cachePayload.Set(cacheKeyBuffer.Bytes(), cacheData, 30)
	if err != nil {
		logp.Err("addCachePayload err = %v, payload = [%s]", err, string(cachePayload.Payload))

		logp.Err("addCachePayload err = %v src_ip = %v, src_port = %d, dst_ip = %v, "+
			"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d, payload = [%s]",
			err, cachePayload.SrcIP, cachePayload.SrcPort, cachePayload.DstIP, cachePayload.DstPort, cachePayload.AckNumber,
			cachePayload.SeqNumber, cachePayload.NextSeqNumber, cachePayload.FrameCount, cachePayload.Payload)
		return false
	}

	return true
}

func (d *Decoder) checkTransport(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, tcp *layers.TCP) (result bool, payLoadList *list.List) {
	ackNumber := tcp.Ack
	seqNumber := tcp.Seq
	payload := tcp.Payload
	cwr := tcp.CWR
	ece := tcp.ECE
	ns := tcp.NS
	checkSum := tcp.Checksum
	window := tcp.Window

	payloadList := list.New()
	payloadLen := len(payload)
	if payloadLen <= 0 {
		return false, payloadList
	}

	timeDelay := time.Now().Sub(d.lastStatTime).Milliseconds()
	if timeDelay > 60*1000 {
		logp.Info("checkTransport expired_count = %d, miss_count = %d, entry_count = %d, "+
			"cwr = %t, ece = %t, ns = %t, check_sum = %d, window = %d",
			d.cachePayload.ExpiredCount(), d.cachePayload.MissCount(), d.cachePayload.EntryCount(),
			cwr, ece, ns, checkSum, window)
		d.lastStatTime = time.Now()
	}

	nextCacheBuffer := bytes.Buffer{}
	nextCacheBuffer.WriteString(srcIP.String())
	nextCacheBuffer.WriteString(strconv.FormatUint(uint64(srcPort), 10))
	nextCacheBuffer.WriteString(dstIP.String())
	nextCacheBuffer.WriteString(strconv.FormatUint(uint64(dstPort), 10))
	//nextCacheBuffer.WriteString(strconv.FormatUint(uint64(ackNumber), 10))
	nextCacheBuffer.WriteString("next")
	nextCacheBuffer.WriteString(strconv.FormatUint(uint64(seqNumber)+uint64(payloadLen), 10))

	lastCacheBuffer := bytes.Buffer{}
	lastCacheBuffer.WriteString(srcIP.String())
	lastCacheBuffer.WriteString(strconv.FormatUint(uint64(srcPort), 10))
	lastCacheBuffer.WriteString(dstIP.String())
	lastCacheBuffer.WriteString(strconv.FormatUint(uint64(dstPort), 10))
	//lastCacheBuffer.WriteString(strconv.FormatUint(uint64(ackNumber), 10))
	lastCacheBuffer.WriteString("last")
	lastCacheBuffer.WriteString(strconv.FormatUint(uint64(seqNumber), 10))

	nextCachePayload := CachePayload{}
	nextPayloadBytes, err := d.cachePayload.Get(nextCacheBuffer.Bytes())
	if err == nil && len(nextPayloadBytes) > 0 {
		if !d.cachePayload.Del(nextCacheBuffer.Bytes()) {
			logp.Err("checkTransport del next cache failed")
		}
		err = json.Unmarshal(nextPayloadBytes, &nextCachePayload)
		if err != nil {
			logp.Err("checkTransport unmarshal next cache err = %v", err)
		}
	}

	lastCachePayload := CachePayload{}
	var lastPayloadBytes []byte
	lastPayloadBytes, err = d.cachePayload.Get(lastCacheBuffer.Bytes())
	if err == nil && len(lastPayloadBytes) > 0 {
		if !d.cachePayload.Del(lastCacheBuffer.Bytes()) {
			logp.Err("checkTransport del last cache failed")
		}
		err = json.Unmarshal(lastPayloadBytes, &lastCachePayload)
		if err != nil {
			logp.Err("checkTransport unmarshal last cache err = %v", err)

		}
	}

	if len(nextPayloadBytes) <= 0 && len(lastPayloadBytes) <= 0 && payloadLen < 10 {
		return false, payloadList
	}

	byteBuffer := bytes.Buffer{}
	processCachePayload := CachePayload{}
	if len(lastCachePayload.Payload) > 0 {
		if seqNumber == lastCachePayload.NextSeqNumber {
			byteBuffer.Write(lastCachePayload.Payload)
		} else {
			if lastCachePayload.SeqNumber != seqNumber ||
				lastCachePayload.NextSeqNumber != (seqNumber+uint32(payloadLen)) ||
				!bytes.Equal(lastCachePayload.Payload, payload) {
				logp.Err("checkTransport retransmission payload src_ip = %v, src_port = %d, dst_ip = %v, "+
					"dst_port = %d, last_ack_number = %d, ack_number = %d, last_seq_number = %d, last_next_seq_number = %d, "+
					"seq_number = %d, next_seq_number = %d, last_frame_count = %d",
					srcIP, srcPort, dstIP, dstPort, lastCachePayload.AckNumber, ackNumber, lastCachePayload.SeqNumber,
					lastCachePayload.NextSeqNumber, seqNumber, seqNumber+uint32(payloadLen), lastCachePayload.FrameCount)
				logp.Err("checkTransport retransmission last = [%s], current = [%s]", string(lastCachePayload.Payload), string(payload))
			}
		}
		processCachePayload.SeqNumber = lastCachePayload.SeqNumber
	} else {
		processCachePayload.SeqNumber = seqNumber
	}
	byteBuffer.Write(payload)
	if len(nextCachePayload.Payload) > 0 {
		if (seqNumber + uint32(payloadLen)) == nextCachePayload.SeqNumber {
			byteBuffer.Write(nextCachePayload.Payload)
		} else {
			if nextCachePayload.SeqNumber != seqNumber ||
				nextCachePayload.NextSeqNumber != (seqNumber+uint32(payloadLen)) ||
				!bytes.Equal(nextCachePayload.Payload, payload) {
				logp.Err("checkTransport retransmission payload src_ip = %v, src_port = %d, dst_ip = %v, "+
					"dst_port = %d, next_ack_number = %d, ack_number = %d, next_seq_number = %d, next_next_seq_number = %d, "+
					"seq_number = %d, next_seq_number = %d, next_frame_count = %d",
					srcIP, srcPort, dstIP, dstPort, nextCachePayload.AckNumber, ackNumber, nextCachePayload.SeqNumber,
					nextCachePayload.NextSeqNumber, seqNumber, seqNumber+uint32(payloadLen), nextCachePayload.FrameCount)
				logp.Err("checkTransport retransmission next = [%s], current = [%s]", string(nextCachePayload.Payload), string(payload))
			}
		}

		processCachePayload.NextSeqNumber = nextCachePayload.NextSeqNumber
	} else {
		processCachePayload.NextSeqNumber = seqNumber + uint32(payloadLen)
	}

	processCachePayload.SrcIP = srcIP
	processCachePayload.SrcPort = srcPort
	processCachePayload.DstIP = dstIP
	processCachePayload.DstPort = dstPort
	processCachePayload.AckNumber = ackNumber
	processCachePayload.FrameCount = lastCachePayload.FrameCount + nextCachePayload.FrameCount + 1

	if len(lastCachePayload.Payload) > 0 && len(nextCachePayload.Payload) > 0 {
		logp.Info("checkTransport combine last and next payload src_ip = %v, src_port = %d, dst_ip = %v, "+
			"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
			srcIP, srcPort, dstIP, dstPort, ackNumber, processCachePayload.SeqNumber,
			processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
		logp.Info("checkTransport combine last and next last = [%s], current = [%s], next = [%s]",
			string(lastCachePayload.Payload), string(payload), string(nextCachePayload.Payload))
	}

	currentPayLoad := byteBuffer.Bytes()
	processCacheByteBuffer := bytes.Buffer{}
	processCount := 0
	for {
		if len(currentPayLoad) <= 0 {
			break
		}

		processCount++
		if processCount > 30 {
			logp.Err("checkTransport invalid process src_ip = %v, src_port = %d, dst_ip = %v, "+
				"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
				srcIP, srcPort, dstIP, dstPort, ackNumber, processCachePayload.SeqNumber,
				processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
			logp.Err("checkTransport invalid process full_payload = [%s], current_payload = [%s]",
				string(byteBuffer.Bytes()), string(currentPayLoad))
			break
		}

		posHeaderEnd := bytes.Index(currentPayLoad, []byte("\r\n\r\n"))
		if posHeaderEnd < 0 {
			processCacheByteBuffer.Write(currentPayLoad)
			break
		}

		if posHeaderEnd == 0 && bytes.Index(currentPayLoad, []byte("\r\n\r\n\r\n\r\n")) == 0 {
			currentPayLoad = currentPayLoad[4:]
			continue
		}

		// Split in headers and content
		headers := currentPayLoad[:posHeaderEnd+4] // keep separator
		content := currentPayLoad[posHeaderEnd+4:] // strip separator
		currentContentLen := len(content)

		headerLines := bytes.Split(headers, []byte("\r\n"))
		headerPos := 0
		for indexHeader := 0; indexHeader < len(headerLines); indexHeader++ {
			headerLine := string(headerLines[indexHeader])
			indexStartLine := startLineRequest(headerLine)
			if indexStartLine < 0 {
				indexStartLine = startLineResponse(headerLine)
			}

			if indexStartLine >= 0 {
				headerPos += indexStartLine
				break
			}

			if strings.Contains(headerLine, "SIP/2.0 200 OK") {
				logp.Err("checkTransport invalid header line src_ip = %v, src_port = %d, dst_ip = %v, "+
					"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
					srcIP, srcPort, dstIP, dstPort, ackNumber, processCachePayload.SeqNumber,
					processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
				logp.Err("checkTransport invalid header line full_payload = [%s], current_payload = [%s]",
					string(byteBuffer.Bytes()), string(currentPayLoad))
			}

			if indexHeader == len(headerLines)-1 {
				headerPos += len(headerLine)
			} else {
				headerPos += len(headerLine) + 2
			}
		}
		if headerPos > 0 {
			if headerPos > len(headers) {
				headerPos = len(headers)
			}

			processCacheByteBuffer.Write(headers[:headerPos])
			if headerPos >= len(headers) {
				currentPayLoad = content
				continue
			}
			headers = headers[headerPos:]
		}

		callID, err := getHeaderValue(callIdHeaderNames, headers)
		if err != nil || len(callID) <= 0 {
			logp.Err("checkTransport no call_id err = %s, src_ip = %v, src_port = %d, dst_ip = %v, "+
				"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
				err.Error(), srcIP, srcPort, dstIP, dstPort, ackNumber, processCachePayload.SeqNumber,
				processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
			logp.Err("checkTransport no call_id full_payload = [%s], current_payload = [%s]",
				string(byteBuffer.Bytes()), string(currentPayLoad))
			currentPayLoad = content
			continue
		}

		contentLength := -1
		contentLengthValue, err := getHeaderValue(contentLengthHeaderNames, headers)
		if err == nil && len(contentLengthValue) > 0 {
			contentLength, _ = strconv.Atoi(strings.TrimSpace(string(contentLengthValue)))
		}
		if contentLength < 0 {
			logp.Err("checkTransport invalid content_length src_ip = %v, src_port = %d, dst_ip = %v, "+
				"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
				srcIP, srcPort, dstIP, dstPort, ackNumber, processCachePayload.SeqNumber,
				processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
			logp.Err("checkTransport invalid content_length full_payload = [%s], current_payload = [%s]",
				string(byteBuffer.Bytes()), string(currentPayLoad))
			currentPayLoad = content
			continue
		}

		if contentLength > currentContentLen {
			processCacheByteBuffer.Write(headers)
			processCacheByteBuffer.Write(content)
			currentPayLoad = nil
			break
		}

		sipPayloadBuffer := bytes.Buffer{}
		sipPayloadBuffer.Write(headers)
		sipPayloadBuffer.Write(content[:contentLength])
		payloadList.PushBack(sipPayloadBuffer.Bytes())
		currentPayLoad = content[contentLength:]

		if contentLength < currentContentLen {
			logp.Info("checkTransport multi payload content_length = %d, current_content_len = %d, call_id = %s, src_ip = %v, src_port = %d, dst_ip = %v, "+
				"dst_port = %d, ack_number = %d, seq_number = %d, next_seq_number = %d, frame_count = %d",
				contentLength, currentContentLen, string(callID), srcIP, srcPort, dstIP, dstPort, ackNumber,
				processCachePayload.SeqNumber, processCachePayload.NextSeqNumber, processCachePayload.FrameCount)
			logp.Info("checkTransport multi payload content_length full_payload = [%s], current_payload = [%s]",
				string(byteBuffer.Bytes()), string(currentPayLoad))
		}
	}

	processCachePayload.Payload = processCacheByteBuffer.Bytes()
	d.addCachePayload(&processCachePayload)

	return true, payloadList
}

func (d *Decoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, sctp *layers.SCTP, flow gopacket.Flow, ci *gopacket.CaptureInfo, IPVersion, IPProtocol uint8, sIP, dIP net.IP) {
	if config.Cfg.DiscardIP != "" {
		for _, v := range d.filterIP {
			if dIP.String() == v {
				logp.Debug("discarding destination IP", dIP.String())
				return
			}
			if sIP.String() == v {
				logp.Debug("discarding source IP", sIP.String())
				return
			}
		}
	}
	if config.Cfg.DiscardSrcIP != "" {
		for _, v := range d.filterSrcIP {
			if sIP.String() == v {
				logp.Debug("discarding source IP", sIP.String())
				return
			}
		}
	}
	if config.Cfg.DiscardDstIP != "" {
		for _, v := range d.filterDstIP {
			if dIP.String() == v {
				logp.Debug("discarding destination IP", dIP.String())
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

	var payloadList *list.List
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
			logp.Debug("payload - UDP", string(pkt.Payload))

			// HPERM layer check
			if pkt.SrcPort == 7932 || pkt.DstPort == 7932 {
				pkt := gopacket.NewPacket(pkt.Payload, d.hperm.LayerType(), gopacket.NoCopy)
				HPERML := pkt.Layer(d.hperm.LayerType())
				if HPERML != nil {
					logp.Info("HPERM layer detected!")
					HPERMpkt, _ := HPERML.(*ownlayers.HPERM)
					//HPERMContent := HPERMpkt.LayerContents()
					HPERMPayload := HPERMpkt.LayerPayload()
					//logp.Info("HPERM Content:", HPERMContent)
					//logp.Info("Payload: ", HPERMPayload)
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
			atomic.AddUint64(&d.tcpCount, 1)
			logp.Debug("payload", "TCP", pkt)

			if config.Cfg.Reassembly {
				d.asm.AssembleWithTimestamp(flow, tcp, ci.Timestamp)
				return
			}

			if config.Cfg.SipAssembly {
				var checkResult bool
				checkResult, payloadList = d.checkTransport(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, tcp)
				if !checkResult || payloadList.Len() <= 0 {
					return
				}

				payloadList.PushBack(pkt.Payload)

				for elem := payloadList.Front(); elem != nil; elem = elem.Next() {
					extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, elem.Value.([]byte))
				}
			} else {
				pkt.Payload = tcp.Payload
				extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)
			}

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
	if payloadList != nil && payloadList.Len() > 0 {
		for elem := payloadList.Front(); elem != nil; elem = elem.Next() {
			pkt2 := &Packet{
				Version:   pkt.Version,
				Protocol:  pkt.Protocol,
				SrcIP:     pkt.SrcIP,
				DstIP:     pkt.DstIP,
				SrcPort:   pkt.SrcPort,
				DstPort:   pkt.DstPort,
				Tsec:      pkt.Tsec,
				Tmsec:     pkt.Tmsec,
				ProtoType: pkt.ProtoType,
				CID:       pkt.CID,
				Vlan:      pkt.Vlan,
			}
			pkt2.Payload = elem.Value.([]byte)
			if cPos = bytes.Index(pkt2.Payload, []byte("CSeq")); cPos > -1 {
				pkt2.ProtoType = 1
			} else if cPos = bytes.Index(pkt2.Payload, []byte("Cseq")); cPos > -1 {
				pkt2.ProtoType = 1
			}
			if cPos > 16 {
				if s := bytes.Index(pkt2.Payload[:cPos], []byte("Sip0")); s > -1 {
					pkt2.Payload = pkt2.Payload[s+4:]
				}
			}

			if pkt2.ProtoType > 0 && pkt2.Payload != nil {
				PacketQueue <- pkt2
			} else {
				atomic.AddUint64(&d.unknownCount, 1)
			}
		}
	} else {
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
}

func (d *Decoder) ProcessHEPPacket(data []byte) {

	if config.Cfg.DiscardMethod != "" {
		h, err := DecodeHEP(data)
		if err == nil {
			c := internal.ParseCSeq([]byte(h.Payload))
			if c != nil {
				for _, v := range d.filter {
					if string(c) == v {
						return
					}
				}
			}
		}
	}

	pkt := &Packet{
		Version: 100,
		Payload: data,
	}
	atomic.AddUint64(&d.hepCount, 1)

	PacketQueue <- pkt
}

func (d *Decoder) SendPingHEPPacket() {

	var data = []byte{0x48, 0x45, 0x50, 0x33, 0x3, 0xa}
	pkt := &Packet{
		Version: 0,
		Payload: data,
	}

	atomic.AddUint64(&d.hepCount, 1)

	PacketQueue <- pkt
}

func (d *Decoder) SendExitHEPPacket() {

	var data = []byte{0x48, 0x45, 0x50, 0x33, 0x3, 0xa}
	pkt := &Packet{
		Version: 255,
		Payload: data,
	}

	PacketQueue <- pkt
}

func stb(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	var res []byte

	bh := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return res
}

// Packet
func (pkt *Packet) GetVersion() uint32 {
	if pkt != nil {
		return uint32(pkt.Version)
	}
	return 0
}

func (pkt *Packet) GetProtocol() uint32 {
	if pkt != nil {
		return uint32(pkt.Protocol)
	}
	return 0
}

func (pkt *Packet) GetSrcIP() string {
	if pkt != nil {
		return pkt.SrcIP.String()
	}
	return ""
}

func (pkt *Packet) GetDstIP() string {
	if pkt != nil {
		return pkt.DstIP.String()
	}
	return ""
}

func (pkt *Packet) GetSrcPort() uint16 {
	if pkt != nil {
		return pkt.SrcPort
	}

	return 0
}

func (pkt *Packet) GetDstPort() uint16 {
	if pkt != nil {
		return pkt.DstPort
	}
	return 0
}

func (pkt *Packet) GetTsec() uint32 {
	if pkt != nil {
		return pkt.Tsec
	}
	return 0
}

func (pkt *Packet) GetTmsec() uint32 {
	if pkt != nil {
		return pkt.Tmsec
	}
	return 0
}

func (pkt *Packet) GetProtoType() uint32 {
	if pkt != nil {
		return uint32(pkt.ProtoType)
	}
	return 0
}

func (pkt *Packet) GetPayload() string {
	if pkt != nil {
		return string(pkt.Payload)
	}
	return ""
}

func (pkt *Packet) GetCID() string {
	if pkt != nil {
		return string(pkt.CID)
	}
	return ""
}
