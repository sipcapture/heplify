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
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/protos"
)

type tcpStreamFactory struct{}

type tcpStream struct {
	net, transport gopacket.Flow
	readerStream   readerStream
}

func (s *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	rs := &tcpStream{
		net:          net,
		transport:    transport,
		readerStream: newReaderStream(),
	}
	go rs.run()
	return &rs.readerStream
}

type readerStream struct {
	tcpreader.ReaderStream
	InitialTS time.Time
}

func newReaderStream() readerStream {
	return readerStream{
		ReaderStream: tcpreader.NewReaderStream(),
	}
}

func (r *readerStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	if r.InitialTS.IsZero() && len(reassembly) > 0 {
		r.InitialTS = reassembly[0].Seen
	}
	r.ReaderStream.Reassembled(reassembly)
}

func (s *tcpStream) run() {
	var data []byte
	var tmp = make([]byte, 4096)
	ts := time.Now()
	for {
		n, err := s.readerStream.Read(tmp)
		if err == io.EOF {
			return
		} else if err != nil {
			logp.Err("got %v while reading temporary buffer", err)
			continue
		} else if n > 0 {
			/* we should make a correct timestamp */
			if data == nil {
				ts = time.Now()
			}

			data = append(data, tmp[0:n]...)

			if bytes.HasPrefix(data, []byte("GET")) || bytes.HasPrefix(data, []byte("HTTP")) {
				data = nil
				continue
			}

			var d []byte
			var isWS bool
			if (data[0] == 129 || data[0] == 130) && (data[1] == 126 || data[1] == 254) {
				d, err = protos.WSPayload(data)
				if err == nil {
					isWS = true
				}
			}

			if isWS || isSIP(data) {
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
				pkt.ProtoType = 1
				pkt.Payload = data
				if isWS {
					pkt.Payload = d
				}
				data = nil
				PacketQueue <- pkt
				extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)
				//logp.Debug("tcpassembly", "%s", pkt)
				//fmt.Printf("###################\n%s", pkt.Payload)
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
	[]byte("SIP/2.0 "),
	[]byte("INVITE "),
	[]byte("REGISTER "),
	[]byte("ACK "),
	[]byte("BYE "),
	[]byte("CANCEL "),
	[]byte("OPTIONS "),
	[]byte("PUBLISH "),
	[]byte("INFO "),
	[]byte("PRACK "),
	[]byte("SUBSCRIBE "),
	[]byte("NOTIFY "),
	[]byte("UPDATE "),
	[]byte("MESSAGE "),
	[]byte("REFER "),
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
