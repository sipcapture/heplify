package decoder

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/negbie/heplify/config"
	"github.com/negbie/logp"
)

type tcpStreamFactory struct{}
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	ident          string
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logp.Info("new stream %s %s\n", net, transport)
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		optchecker: reassembly.NewTCPOptionCheck(),
		ident:      fmt.Sprintf("%s:%s", net, transport),
	}
	return stream
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, acked reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		logp.Err("%s: packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		if !t.fsmerr {
			t.fsmerr = true
		}
		// TODO: make a flag for this
		if false {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, acked, start)
	if err != nil {
		logp.Err("%s: packet rejected by OptionChecker: %s\n", t.ident, err)
		// TODO: make a flag for this
		if false {
			return false
		}
	}
	// Checksum
	accept := true
	// TODO: make a flag for this
	if true {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			logp.Err("%s: error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			logp.Err("%s: invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()

	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		logp.Err("invalid overlap bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		//panic("Invalid overlap")
		return
	}

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	logp.Info("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	data := sg.Fetch(length)
	pkt := &Packet{
		SrcIP:     t.net.Src().Raw(),
		DstIP:     t.net.Dst().Raw(),
		SrcPort:   binary.BigEndian.Uint16(t.transport.Src().Raw()),
		DstPort:   binary.BigEndian.Uint16(t.transport.Dst().Raw()),
		Tsec:      uint32(time.Now().Unix()),
		Tmsec:     uint32(time.Now().Nanosecond() / 1000),
		ProtoType: 1,
		NodeID:    uint32(config.Cfg.HepNodeID),
		NodePW:    []byte(config.Cfg.HepNodePW),
		Payload:   data,
	}
	logp.Info("%v %v", string(data), pkt)
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logp.Info("%s: Connection closed\n", t.ident)
	// do not remove the connection to allow last ACK
	return false
}

/* func (t *tcpStream) run() {
	splitPackets(t.net, t.transport, &t.reader)
	io.Copy(ioutil.Discard, &t.reader)
} */

func splitPackets(netFlow, transFlow gopacket.Flow, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanCRLFCRLF)
	logp.Info("%v %v", netFlow, transFlow)
	for scanner.Scan() {
		logp.Info("%s", scanner.Text())
	}
}

func scanCRLFCRLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte{'\r', '\n', '\r', '\n'}); i >= 0 {
		return i + 4, data[0:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
