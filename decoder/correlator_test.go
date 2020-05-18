package decoder

import (
	"bytes"
	"log"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/freecache"
	"github.com/sipcapture/heplify/config"
)

func createUpToUDPLayer(srcIP, dstIP string, srcPort, dstPort uint16) (*layers.Ethernet, *layers.IPv4, *layers.UDP) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	return ethLayer, ipLayer, udpLayer
}

func createUDPSIPPacket() []byte {
	ethLayer, ipLayer, udpLayer := createUpToUDPLayer("200.57.7.204", "200.57.7.195", 5061, 5060)

	payload := []byte("SIP/2.0 200 Ok\r\n" +
		"Via: SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290\r\n" +
		"Via: SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0\r\n" +
		"From: <sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n" +
		"To: \"francisco@bestel.com\" <sip:francisco@bestel.com:55060>;tag=298852044\r\n" +
		"Contact: <sip:francisco@200.57.7.204:5061>\r\n" +
		"Call-ID: 12013223@200.57.7.195\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Server: X-Lite release 1103m\r\n" +
		"Content-Length: 298\r\n\r\n" +
		"v=0\r\n" +
		"o=francisco 13004970 13013442 IN IP4 200.57.7.204\r\n" +
		"s=X-Lite\r\n" +
		"c=IN IP4 200.57.7.204\r\n" +
		"t=0 0\r\n" +
		"m=audio 8000 RTP/AVP 8 0 3 98 97 101\r\n" +
		"a=rtcp:8001\r\n" +
		"a=rtpmap:0 pcmu/8000\r\n" +
		"a=rtpmap:8 pcma/8000\r\n" +
		"a=rtpmap:3 gsm/8000\r\n" +
		"a=rtpmap:98 iLBC/8000\r\n" +
		"a=rtpmap:97 speex/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-15\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		log.Panic()
	}

	return buffer.Bytes()
}

func createUDPRTCPPacket() []byte {
	ethLayer, ipLayer, udpLayer := createUpToUDPLayer("200.57.7.204", "200.57.7.196", 8001, 40377)

	payload := []byte{
		0x81, 0xc8, 0x0, 0xc, 0xd2, 0xbd, 0x4e, 0x3e, 0xc5, 0x92,
		0x86, 0xd4, 0xe6, 0xe9, 0x78, 0xd5, 0x0, 0x0, 0x1, 0x40,
		0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x1, 0x40, 0xd2, 0xbd,
		0x4e, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2,
		0x0, 0x0, 0x0, 0x0, 0x86, 0xd4, 0xe6, 0xe9, 0x0,
		0x0, 0x0, 0x1, 0x81, 0xc9, 0x0, 0x7, 0xd2, 0xbd,
		0x4e, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x86, 0xd4, 0xe6, 0xe9, 0x0,
		0x0, 0x0, 0x1}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		log.Panic()
	}

	return buffer.Bytes()
}

func newTestDecoder() (*Decoder, gopacket.CaptureInfo) {
	config.Cfg.Dedup = false
	//config.Cfg.DiscardMethod = "REGISTER"
	//config.Cfg.Mode = "SIPLOG"
	d := NewDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: 715, Length: 715, InterfaceIndex: 4}
	go func() {
		for {
			select {
			case _ = <-PacketQueue:
			}
		}
	}()
	return d, ci
}

func printCache(n string, c *freecache.Cache) {
	i := c.NewIterator()
	log.Printf("found following key value pairs in %s:\n", n)
	for {
		e := i.Next()
		if e == nil {
			break
		}
		if e.Key != nil {
			log.Printf("key:%q value:%q\n", e.Key, e.Value)
		}
	}
}

var (
	SIPCallID   = []byte("12013223@200.57.7.195")
	SDPSrcIP    = []byte("200.57.7.204")
	SDPRTPPort  = []byte("8000")
	SDPRTCPPort = []byte("8001")
	RTCPSSRC    = []byte{0xd2, 0xbd, 0x4e, 0x3e}

	// CIDKey is srcIP + " " + srcPort
	CIDKey = bytes.Join([][]byte{SDPSrcIP, SDPRTCPPort}, []byte(" "))
	// RTCPKey is srcIP + " " + srcPort + " " + SSRC
	RTCPKey = bytes.Join([][]byte{CIDKey, RTCPSSRC}, []byte(" "))
)

func TestCacheSDPIPPort(t *testing.T) {
	d, ci := newTestDecoder()
	d.Process(createUDPSIPPacket(), &ci)
	d.Process(createUDPRTCPPacket(), &ci)

	//printCache("cidCache", cidCache)

	v, err := cidCache.Get(CIDKey)
	if err != nil || !bytes.Equal(SIPCallID, v) {
		log.Printf("want:%s but got:%s\n", SIPCallID, v)
		t.Fail()
	}
}

func TestCorrelateRTCP(t *testing.T) {
	d, ci := newTestDecoder()
	d.Process(createUDPSIPPacket(), &ci)
	d.Process(createUDPRTCPPacket(), &ci)

	//printCache("rtcpCache", rtcpCache)

	v, err := rtcpCache.Get(RTCPKey)
	if err != nil || !bytes.Equal(SIPCallID, v) {
		log.Printf("want:%s but got:%s\n", SIPCallID, v)
		t.Fail()
	}
}

func BenchmarkProcess(b *testing.B) {
	d, ci := newTestDecoder()
	sipPacket := createUDPSIPPacket()
	rtcpPacket := createUDPRTCPPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Process(sipPacket, &ci)
		d.Process(rtcpPacket, &ci)
	}
}
