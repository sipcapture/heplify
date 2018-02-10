package publish

import (
	"bufio"
	"crypto/tls"
	"net"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

type HEPOutputer struct {
	addr     string
	conn     net.Conn
	writer   *bufio.Writer
	hepQueue chan []byte
}

func NewHEPOutputer(serverAddr string) (*HEPOutputer, error) {
	ho := &HEPOutputer{
		addr:     serverAddr,
		hepQueue: make(chan []byte),
	}

	if err := ho.Init(); err != nil {
		return nil, err
	}

	go ho.Start()
	return ho, nil
}

func (ho *HEPOutputer) Init() error {
	var err error
	if ho.conn, err = ho.ConnectServer(ho.addr); err != nil {
		return err
	}

	w := bufio.NewWriter(ho.conn)
	ho.writer = w

	return nil
}

func (ho *HEPOutputer) Close() {
	if err := ho.conn.Close(); err != nil {
		logp.Err("close connection error: %v", err)
	}
}

func (ho *HEPOutputer) ReConnect() error {
	var err error
	if ho.conn != nil {
		ho.Close()
		logp.Info("close old connection")
	}

	logp.Info("reconnect server")
	if ho.conn, err = ho.ConnectServer(ho.addr); err != nil {
		return err
	}

	logp.Info("reconnect successfull")
	ho.writer.Reset(ho.conn)

	return nil
}

func (ho *HEPOutputer) ConnectServer(addr string) (conn net.Conn, err error) {
	if config.Cfg.HepTLSProxy == "" {
		if ho.conn, err = net.Dial("udp", addr); err != nil {
			return nil, err
		}
	} else {
		if ho.conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err != nil {
			return nil, err
		}
	}
	return ho.conn, nil
}

func (ho *HEPOutputer) Output(pkt *decoder.Packet) {
	ho.hepQueue <- EncodeHEP(pkt)
}

func (ho *HEPOutputer) Send(msg []byte) {
	_, err := ho.writer.Write(msg)

	if err != nil {
		logp.Err("write error: %v", err)

		if err = ho.ReConnect(); err != nil {
			logp.Err("reconnect error: %v", err)
			return
		}

		if _, err = ho.writer.Write(msg); err != nil {
			logp.Err("rewrite error: %v", err)
		}
	}

	if err = ho.writer.Flush(); err != nil {
		logp.Err("flush error: %v", err)
	}
}

func (ho *HEPOutputer) Start() {
	for {
		select {
		case msg := <-ho.hepQueue:
			ho.Send(msg)
		}
	}
}
