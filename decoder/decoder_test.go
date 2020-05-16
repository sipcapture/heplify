package decoder

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/freecache"
	"github.com/sipcapture/heplify/config"
)

// rawSIPLayer contains following IP's and Port's:
var (
	rawSIPLayerSrcIPPort = []byte("200.57.7.204 5061")
	rawSIPLayerDstIPPort = []byte("200.57.7.195 5060")
	rawSIPLayer          = []byte{0x0, 0x3, 0xba, 0x94, 0x63, 0x3e, 0x0, 0x0, 0x0, 0x60, 0xdd, 0x19, 0x8, 0x0, 0x45, 0x0, 0x3, 0x30, 0x11, 0xb5, 0x0, 0x0, 0x80, 0x11, 0x86, 0x6, 0xc8, 0x39, 0x7, 0xcc, 0xc8, 0x39, 0x7, 0xc3, 0x13, 0xc5, 0x13, 0xc4, 0x3, 0x1c, 0x1f, 0xa3}
)

var (
	SIPCallID     = []byte("12013223@200.57.7.195")
	SDPSrcIP      = []byte("200.57.7.204")
	SDPRTPPort    = []byte("8000")
	SDPRTCPPort   = []byte("8001")
	SDPIPRTCPPort = bytes.Join([][]byte{SDPSrcIP, SDPRTCPPort}, []byte(" "))

	SIP = []byte("SIP/2.0 200 Ok\r\n" +
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
		"a=rtpmap:0 pcmu/8000\r\n" +
		"a=rtpmap:8 pcma/8000\r\n" +
		"a=rtpmap:3 gsm/8000\r\n" +
		"a=rtpmap:98 iLBC/8000\r\n" +
		"a=rtpmap:97 speex/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-15\r\n")
)

// rawRTCPPacket contains following IP's and Port's:
var (
	rawRTCPPacketSrcIPPort = []byte("200.57.7.204 8001")
	rawRTCPPacketDstIPPort = []byte("200.57.7.196 40377")
	rawRTCPSSRC            = []byte{0xd2, 0xbd, 0x4e, 0x3e}
	rawRTCPKey             = bytes.Join([][]byte{rawRTCPPacketSrcIPPort, rawRTCPSSRC}, []byte(" "))
	rawRTCPPacket          = []byte{0x0, 0x11, 0x43, 0x37, 0x75, 0x9b, 0x0, 0x0, 0x0, 0x60, 0xdd, 0x19, 0x8, 0x0, 0x45, 0x0, 0x0, 0x70, 0x11, 0xb8, 0x0, 0x0, 0x80, 0x11, 0x88, 0xc2, 0xc8, 0x39, 0x7, 0xcc, 0xc8, 0x39, 0x7, 0xc4, 0x1f, 0x41, 0x9d, 0xb9, 0x0, 0x5c, 0xb1, 0x73, 0x81, 0xc8, 0x0, 0xc, 0xd2, 0xbd, 0x4e, 0x3e, 0xc5, 0x92, 0x86, 0xd4, 0xe6, 0xe9, 0x78, 0xd5, 0x0, 0x0, 0x1, 0x40, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x1, 0x40, 0xd2, 0xbd, 0x4e, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x86, 0xd4, 0xe6, 0xe9, 0x0, 0x0, 0x0, 0x1, 0x81, 0xc9, 0x0, 0x7, 0xd2, 0xbd, 0x4e, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x86, 0xd4, 0xe6, 0xe9, 0x0, 0x0, 0x0, 0x1}
)

var rawSIPPacket = bytes.Join([][]byte{rawSIPLayer, SIP}, []byte(""))

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
	fmt.Printf("found following key value pairs in %s:\n", n)
	for {
		e := i.Next()
		if e == nil {
			break
		}
		if e.Key != nil {
			fmt.Printf("key:%q value:%q\n", e.Key, e.Value)
		}
	}
}

func TestCacheSDPIPPort(t *testing.T) {
	d, ci := newTestDecoder()
	d.Process(rawSIPPacket, &ci)
	d.Process(rawRTCPPacket, &ci)

	//printCache("sdpCache", sdpCache)

	v, err := sdpCache.Get(SDPIPRTCPPort)
	if err != nil || !bytes.Equal(SIPCallID, v) {
		fmt.Printf("want:%s but got:%s\n", SIPCallID, v)
		t.Fail()
	}
}

func TestCorrelateRTCP(t *testing.T) {
	d, ci := newTestDecoder()
	d.Process(rawSIPPacket, &ci)
	d.Process(rawRTCPPacket, &ci)

	//printCache("rtcpCache", rtcpCache)

	v, err := rtcpCache.Get(rawRTCPKey)
	if err != nil || !bytes.Equal(SIPCallID, v) {
		fmt.Printf("want:%s but got:%s\n", SIPCallID, v)
		t.Fail()
	}
}

func BenchmarkProcess(b *testing.B) {
	d, ci := newTestDecoder()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Process(rawSIPPacket, &ci)
		d.Process(rawRTCPPacket, &ci)
	}
}
