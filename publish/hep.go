package publish

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

type HepOutputer struct {
	addr     string
	writer   *bufio.Writer
	hepQueue chan []byte
}

func NewHepOutputer(serverAddr string) (*HepOutputer, error) {
	ho := &HepOutputer{
		addr:     serverAddr,
		hepQueue: make(chan []byte, 1024),
	}
	err := ho.Init()
	if err != nil {
		return nil, err
	}
	go ho.Start()
	return ho, nil
}

func (ho *HepOutputer) Init() error {
	conn, err := ho.ConnectServer(ho.addr)
	if err != nil {
		logp.Err("server connection error: %v", err)
		return err
	}
	w := bufio.NewWriter(conn)
	ho.writer = w
	return nil
}

func (ho *HepOutputer) Close() {
	logp.Info("connection close.")
}

func (ho *HepOutputer) ReConnect() error {
	logp.Warn("reconnect server.")
	conn, err := ho.ConnectServer(ho.addr)
	if err != nil {
		logp.Err("reconnect server error: %v", err)
		return err
	}
	w := bufio.NewWriter(conn)
	ho.writer = w
	return nil
}

func (ho *HepOutputer) ConnectServer(addr string) (conn net.Conn, err error) {
	conn, err = net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (ho *HepOutputer) Output(msg []byte) {
	ho.hepQueue <- msg
}

func (ho *HepOutputer) Send(msg []byte) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("send msg error: %v", err)
		}
	}()

	_, err := ho.writer.Write(msg)

	if err != nil {
		err = ho.ReConnect()
		if err != nil {
			logp.Err("reconnect error: %v", err)
			return
		}
		logp.Debug("hep", "reconnect successfull")
		_, err := ho.writer.Write(msg)
		if err != nil {
			logp.Err("resend to server error: %v", err)
		}
		err = ho.writer.Flush()
		if err != nil {
			logp.Err("flush error: %v", err)
		}
		return
	}
	err = ho.writer.Flush()
	if err != nil {
		logp.Err("flush error: %v", err)
		return
	}
}

func (ho *HepOutputer) Start() {
	counter := 0
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover() error: %v", err)
		}
		ho.Close()
	}()

	for {
		select {
		case msg := <-ho.hepQueue:
			counter++
			ho.Send(msg)
		}
		if counter%65536 == 0 {
			logp.Info("msg=\"HEP packets sent: %d\"", counter)
		}
	}
}

func NewHEP(h *decoder.Packet) []byte {
	chuncks := newHEPChuncks(h)
	hepMsg := make([]byte, len(chuncks)+6)
	copy(hepMsg[6:], chuncks)
	binary.BigEndian.PutUint32(hepMsg[:4], uint32(0x48455033))
	binary.BigEndian.PutUint16(hepMsg[4:6], uint16(len(hepMsg)))
	return hepMsg
}

// MakeChunck will construct the respective HEP chunck
func makeChunck(chunckVen uint16, chunckType uint16, h *decoder.Packet) []byte {
	var chunck []byte
	switch chunckType {
	// Chunk IP protocol family (0x02=IPv4)
	case 0x0001:
		chunck = make([]byte, 6+1)
		chunck[6] = h.Version

	// Chunk IP protocol ID (0x11=UDP)
	case 0x0002:
		chunck = make([]byte, 6+1)
		chunck[6] = h.Protocol

	// Chunk IPv4 source address
	case 0x0003:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Srcip)

	// Chunk IPv4 destination address
	case 0x0004:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Dstip)

	// Chunk IPv6 source address
	// case 0x0005:

	// Chunk IPv6 destination address
	// case 0x0006:

	// Chunk protocol source port
	case 0x0007:
		chunck = make([]byte, 6+2)
		binary.BigEndian.PutUint16(chunck[6:], h.Sport)

	// Chunk destination source port
	case 0x0008:
		chunck = make([]byte, 6+2)
		binary.BigEndian.PutUint16(chunck[6:], h.Dport)

	// Chunk unix timestamp, seconds
	case 0x0009:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Tsec)

	// Chunk unix timestamp, microseconds offset
	case 0x000a:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], h.Tmsec)

	// Chunk protocol type (SIP/H323/RTP/MGCP/M2UA)
	case 0x000b:
		chunck = make([]byte, 6+1)
		if config.Cfg.Mode == "SIP" {
			chunck[6] = 1 // SIP
		} else {
			chunck[6] = 100 // LOG
		}

	// Chunk capture agent ID
	case 0x000c:
		chunck = make([]byte, 6+4)
		binary.BigEndian.PutUint32(chunck[6:], 0x00001111)

	// Chunk keep alive timer
	// case 0x000d:

	// Chunk authenticate key (plain text / TLS connection)
	case 0x000e:
		chunck = make([]byte, len("myhep")+6)
		copy(chunck[6:], "myhep")

	// Chunk captured packet payload
	case 0x000f:
		chunck = make([]byte, len(h.Payload)+6)
		copy(chunck[6:], h.Payload)

	// Chunk captured compressed payload (gzip/inflate)
	// case 0x0010:

	// Chunk internal correlation id
	case 0x0011:
		chunck = make([]byte, len(h.CorrelationID)+6)
		copy(chunck[6:], h.CorrelationID)

	// Chunk MOS only
	case 0x0020:
		//chunck = make([]byte, 6+2)
		//binary.BigEndian.PutUint16(chunck[6:], uint16())
	}

	binary.BigEndian.PutUint16(chunck[:2], chunckVen)
	binary.BigEndian.PutUint16(chunck[2:4], chunckType)
	binary.BigEndian.PutUint16(chunck[4:6], uint16(len(chunck)))
	return chunck
}

// NewHEPChuncks will fill a buffer with all the chuncks
func newHEPChuncks(h *decoder.Packet) []byte {
	buf := new(bytes.Buffer)

	buf.Write(makeChunck(0x0000, 0x0001, h))
	buf.Write(makeChunck(0x0000, 0x0002, h))
	buf.Write(makeChunck(0x0000, 0x0003, h))
	buf.Write(makeChunck(0x0000, 0x0004, h))
	buf.Write(makeChunck(0x0000, 0x0007, h))
	buf.Write(makeChunck(0x0000, 0x0008, h))
	buf.Write(makeChunck(0x0000, 0x0009, h))
	buf.Write(makeChunck(0x0000, 0x000a, h))
	buf.Write(makeChunck(0x0000, 0x000b, h))
	buf.Write(makeChunck(0x0000, 0x000c, h))
	buf.Write(makeChunck(0x0000, 0x000e, h))
	buf.Write(makeChunck(0x0000, 0x000f, h))
	if config.Cfg.Mode != "SIP" {
		buf.Write(makeChunck(0x0000, 0x0011, h))
	}
	return buf.Bytes()
}
