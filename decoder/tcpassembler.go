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

type streamFactory struct{}
type stream struct {
	netFlow   gopacket.Flow
	transFlow gopacket.Flow
	reader    tcpreader.ReaderStream
}

func (f *streamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	var s = stream{
		netFlow:   netFlow,
		transFlow: transFlow,
		reader:    tcpreader.NewReaderStream(),
	}
	go s.run()
	return &s.reader
}

func (s *stream) run() {
	splitPackets(s.netFlow, s.transFlow, &s.reader)
	io.Copy(ioutil.Discard, &s.reader)
}

func splitPackets(netFlow, transFlow gopacket.Flow, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanCRLF)

	for scanner.Scan() {
		pkt := &Packet{
			SrcIP:     netFlow.Src().Raw(),
			DstIP:     netFlow.Dst().Raw(),
			SrcPort:   binary.BigEndian.Uint16(transFlow.Src().Raw()),
			DstPort:   binary.BigEndian.Uint16(transFlow.Dst().Raw()),
			Tsec:      uint32(time.Now().Unix()),
			Tmsec:     uint32(time.Now().Nanosecond() / 1000),
			ProtoType: 1,
			NodeID:    uint32(config.Cfg.HepNodeID),
			NodePW:    []byte(config.Cfg.HepNodePW),
			Payload:   scanner.Bytes(),
		}
		logp.Info("%s %s", scanner.Text(), pkt)
	}

}

func scanCRLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.LastIndex(data, []byte{'\r', '\n'}); i >= 0 {
		// We have a full newline-terminated line.
		return i + 2, data[0:i], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func scanCRLFCRLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte{'\r', '\n', '\r', '\n'}); i >= 0 {
		// We have a full newline-terminated line.
		return i + 4, data[0:i], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
