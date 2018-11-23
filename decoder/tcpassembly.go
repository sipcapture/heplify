package decoder

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/sipcapture/heplify/config"
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
	var data []byte
	var tmp = make([]byte, 4096)
	for {
		n, err := s.reader.Read(tmp)
		if err == io.EOF {
			return
		} else if err != nil {
			logp.Err("got %v while reading temporary buffer", err)
		} else if n > 0 {
			data = append(data, tmp[0:n]...)
			if isSIP(data) {
				ts := time.Now()
				pkt := &Packet{}
				pkt.Version = 0x02
				pkt.Protocol = 0x06
				pkt.SrcIP = s.net.Src().Raw()
				pkt.DstIP = s.net.Dst().Raw()
				sp := s.transport.Src().Raw()
				dp := s.transport.Dst().Raw()
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
				pkt.Payload = data
				pkt.ProtoType = 1
				PacketQueue <- pkt
				cacheSDPIPPort(pkt.Payload)
				logp.Debug("tcpassembly", "%s", pkt)
				data = nil
			}
		}
	}
}

func isSIP(data []byte) bool {
	end := []byte("\r\n")
	bodyLen := getSIPHeaderValInt("Content-Length:", data)
	if bodyLen < 1 {
		end = []byte("\r\n\r\n")
	} else {
		headerLen := bytes.Index(data, []byte("\r\n\r\n")) + 4
		if headerLen == -1 || headerLen+bodyLen != len(data) {
			return false
		}
	}

	for k := range firstSIPLine {
		if bytes.HasPrefix(data, firstSIPLine[k]) && bytes.HasSuffix(data, end) {
			return true
		}
	}
	return false
}

func isSDP(data []byte) bool {
	for k := range firstSDPLine {
		if bytes.HasPrefix(data, firstSDPLine[k]) && bytes.HasSuffix(data, []byte("\r\n")) {
			return true
		}
	}
	return false
}

func getSIPHeaderValInt(header string, data []byte) (valInt int) {
	l := len(header)
	if startPos := bytes.Index(data, []byte(header)); startPos > -1 {
		restData := data[startPos:]
		if endPos := bytes.Index(restData, []byte("\r\n")); endPos > l {
			val := string(restData[l:endPos])
			i := 0
			for i < len(val) && (val[i] == ' ' || val[i] == '\t') {
				i++
			}
			val = val[i:]
			if valInt, err := strconv.Atoi(val); err == nil {
				return valInt
			}
		}
	}
	return -1
}

var firstSIPLine = [][]byte{
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
	[]byte("SIP/2.0 "),
}

var firstSDPLine = [][]byte{
	[]byte("a="),
	[]byte("b="),
	[]byte("c="),
	[]byte("e="),
	[]byte("i="),
	[]byte("k="),
	[]byte("m="),
	[]byte("o="),
	[]byte("p="),
	[]byte("r="),
	[]byte("s="),
	[]byte("t="),
	[]byte("u="),
	[]byte("v="),
	[]byte("z="),
}
