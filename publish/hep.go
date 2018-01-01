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
	err := ho.Init()
	if err != nil {
		return nil, err
	}
	go ho.Start()
	return ho, nil
}

func (ho *HEPOutputer) Init() error {
	var err error
	if ho.conn, err = ho.ConnectServer(ho.addr); err != nil {
		logp.Err("server connection error: %v", err)
		return err
	}
	w := bufio.NewWriter(ho.conn)
	ho.writer = w
	return nil
}

func (ho *HEPOutputer) Close() {
	logp.Info("close connection.")
	if err := ho.conn.Close(); err != nil {
		logp.Err("close connection error: %v", err)
	}
}

func (ho *HEPOutputer) ReConnect() error {
	logp.Info("reconnect server.")
	var err error
	if ho.conn, err = ho.ConnectServer(ho.addr); err != nil {
		logp.Err("reconnect server error: %v", err)
		return err
	}
	w := bufio.NewWriter(ho.conn)
	ho.writer = w
	return nil
}

func (ho *HEPOutputer) ConnectServer(addr string) (conn net.Conn, err error) {
	if config.Cfg.HepTLSProxy == "" {
		ho.conn, err = net.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
	} else {
		ho.conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}
	return ho.conn, nil
}

func (ho *HEPOutputer) Output(pkt *decoder.Packet) {
	ho.hepQueue <- NewHEP(pkt)
}

func (ho *HEPOutputer) Send(msg []byte) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("send error: %v", err)
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
			logp.Err("reflush error: %v", err)
		}
		return
	}
	err = ho.writer.Flush()
	if err != nil {
		logp.Err("flush error: %v", err)
		return
	}
}

func (ho *HEPOutputer) Start() {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover() error: %v", err)
		}
		ho.Close()
	}()

	for {
		select {
		case msg := <-ho.hepQueue:
			ho.Send(msg)
		}
	}
}
