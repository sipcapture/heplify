package decoder

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/negbie/heplify/config"
	"github.com/negbie/logp"
)

type sipStreamFactory struct{}

type sipStream struct {
	net, transport gopacket.Flow
	reader         tcpreader.ReaderStream
}

func (s *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	st := &sipStream{
		net:       net,
		transport: transport,
		reader:    tcpreader.NewReaderStream(),
	}
	go st.run()
	return &st.reader
}

func (s *sipStream) run() {
	splitPackets(s.net, s.transport, &s.reader)
	io.Copy(ioutil.Discard, &s.reader)
}

func splitPackets(netFlow, transFlow gopacket.Flow, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanSIP)
	for scanner.Scan() {
		ts := time.Now()
		pkt := &Packet{}
		pkt.Version = 0x02
		pkt.Protocol = 0x06
		pkt.SrcIP = netFlow.Src().Raw()
		pkt.DstIP = netFlow.Dst().Raw()
		sp := transFlow.Src().Raw()
		dp := transFlow.Dst().Raw()
		if len(sp) == 2 && len(dp) == 2 {
			pkt.SrcPort = binary.BigEndian.Uint16(sp)
			pkt.DstPort = binary.BigEndian.Uint16(dp)
		}
		if len(pkt.SrcIP) > 4 || len(pkt.DstIP) > 4 {
			pkt.Version = 0x0a
		}
		pkt.Tsec = uint32(ts.Unix())
		pkt.Tmsec = uint32(ts.Nanosecond() / 1000)
		pkt.NodeID = uint32(config.Cfg.HepNodeID)
		pkt.NodePW = []byte(config.Cfg.HepNodePW)
		pkt.Payload = scanner.Bytes()
		if bytes.Contains(pkt.Payload, []byte("CSeq")) {
			pkt.ProtoType = 1
			PacketQueue <- pkt
			cacheSDPIPPort(pkt.Payload)
		}
		logp.Debug("tcpassembly", "%s", pkt)
	}
}

func scanSIP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	for k := range startSIP {
		if bytes.HasPrefix(data, startSIP[k]) && bytes.HasSuffix(data, []byte("\r\n")) || bytes.HasSuffix(data, []byte("\r\n\r\n")) {
			return len(data), data, nil
		}
	}

	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

var startSIP = [][]byte{
	[]byte("INVITE "),
	[]byte("REGISTER "),
	[]byte("ACK "),
	[]byte("BYE "),
	[]byte("CANCEL "),
	[]byte("OPTIONS "),
	[]byte("INFO "),
	[]byte("PRACK "),
	[]byte("SUBSCRIBE "),
	[]byte("NOTIFY "),
	[]byte("UPDATE "),
	[]byte("MESSAGE "),
	[]byte("REFER "),
	[]byte("PUBLISH "),
	[]byte("SIP/"),
}
