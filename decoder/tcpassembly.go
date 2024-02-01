package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
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
	tcpassembly.Stream
	ReassembledChan chan tcpassembly.Reassembly
	Closed bool
}

func newReaderStream() readerStream {
	return readerStream{
		ReassembledChan: make(chan tcpassembly.Reassembly),
		Closed: false,
	}
}

func (r *readerStream) Reassembled(reassembled []tcpassembly.Reassembly) {
	for _, reassembly := range reassembled {
		r.ReassembledChan <- reassembly
	}
}

func (r *readerStream) ReassemblyComplete() {
	close(r.ReassembledChan)
	r.Closed = true
}

func (s *tcpStream) run() {
	var tsUnset time.Time = time.Unix(0, 0)
	var ts time.Time = tsUnset
	var data []byte = make([]byte, 0)
	var reassembly tcpassembly.Reassembly
	var again bool = false
	var ignore bool = false
	for {
		if again {
			// Check remainder of data again without getting next packet.
			again = false
		} else {
			// Get next packet.
			reassembly, more := <- s.readerStream.ReassembledChan
			if !more {
				return
			}
			// logp.Debug("tcpassembly", "src=%s-%s dst=%s-&s reassembly=%s", s.net.Src(), s.transport.Src(), s.net.Dst(), s.transport.Dst(), reassembly)
			// Check for mising data.
			// Missing data is normal. The assembly is flusehd every second, which closes connections which did not receive new data.
			if reassembly.Skip != 0 {
				// logp.Debug("tcpassembly", "detected lost packets")
				// Discard collected data and try to continue
				data = data[0:0]
				ts = tsUnset
			}
			// Should we ignore all packets?
			if ignore {
				continue
			}
			// Skip empty packets.
			if len(reassembly.Bytes) == 0 {
				continue
			}
			// Remember start time.
			if ts == tsUnset {
				ts = reassembly.Seen
			}
			// Collect data.
			data = append(data, reassembly.Bytes...)
			logp.Info("data=", data)
		}

		// Skip if empty.
		if len(data) == 0 {
			continue
		}

		// Check for websocket upgrade.
		if bytes.HasPrefix(data, []byte("GET")) || bytes.HasPrefix(data, []byte("HTTP")) {
			var msgLen = bytes.Index(data, []byte("\r\n\r\n")) + 4
			if msgLen > 4 {
				// Found end of HTTP request/response.
				// Skip this message and start new message.
				data = data[msgLen:]
				if len(data) > 0 {
					again = true
					ts = reassembly.Seen

				} else {
					ts = tsUnset
				}
				continue
			}
		}

		var msgLen int = 0
		var payload []byte
		var err error
		var isWS bool = false
		var isSIP bool = false

		// Check for websocket data.
		if (data[0] == 129 || data[0] == 130) && (data[1] == 126 || data[1] == 254) {
			payload, err = protos.WSPayload(data)  // TODO: will only match if data contains exactly one message.
			if err == nil {
				isWS = true
				msgLen = len(data)  // TODO: should only be the length of the complete WS message.
				// TODO: Should we not check if WS payload contains SIP and handle it?
			}
		} else {
			// Check for SIP mesage.
			payload, err = SIPMessage(data)
			if err == nil {
				isSIP = true
				msgLen = len(payload)
			}
		}
		// logp.Debug("tcpassembly" "isWS=%s isSIP=%s", isWS, isSIP)

		if isWS || isSIP {
			// Build HEP packet.
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
			pkt.Payload = payload
			// logp.Debug("tcpassembly", "%s", pkt)
			//fmt.Printf("###################\n%s", pkt.Payload)
			// Extract information for RTP association.
			extractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)
			// Queue HEP packet.
			PacketQueue <- pkt
			// Remove message from data and check remainder again.
			data = data[msgLen:]
			if len(data) > 0 {
				again = true
				ts = reassembly.Seen

			} else {
				ts = tsUnset
			}
		} else {
			// Check if we accumulated to much data for a SIP message.
			if len(data) > 1000000 {
				// logp.Debug("tcpassembly" "collected to much data, ignoring")
				// Remove data and ignore further data.
				data = data[0:0]
				ignore = true
			}
		}
	}
}

var SIPTruncated = errors.New("not SIP")
var NotSIP = errors.New("not SIP")

func SIPMessage(data []byte) ([]byte, error) {
	// Check that first line looks like SIP.
	hasSIPLine := false
	for k := range firstSIPLine {
		if bytes.HasPrefix(data, firstSIPLine[k]) {
			hasSIPLine = true
			break
		}
	}
	if !hasSIPLine {
		return nil, NotSIP
	}
	// Get length of header.
	headerLen := bytes.Index(data, []byte("\r\n\r\n")) + 4
	if headerLen < 4 {
		return nil, SIPTruncated
	}
	// Get body length.
	bodyLen := getSIPHeaderValInt("Content-Length:", data)
	if bodyLen < 0 {
		// No body.
		bodyLen = 0
	}
	// Check that message is complete.
	if len(data) < headerLen + bodyLen {
		return nil, SIPTruncated
	}
	// Return message.
	return data[:headerLen + bodyLen], nil
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
