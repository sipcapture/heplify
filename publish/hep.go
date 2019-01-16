package publish

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/negbie/heplify/config"
	"github.com/negbie/logp"
)

type HEPOutputer struct {
	addr     string
	conn     net.Conn
	writer   *bufio.Writer
	hepQueue chan []byte
	errCnt   int
}

func NewHEPOutputer(serverAddr string) (*HEPOutputer, error) {
	ho := &HEPOutputer{
		addr:     serverAddr,
		hepQueue: make(chan []byte, 20000),
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

	w := bufio.NewWriterSize(ho.conn, 8192)
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
		logp.Info("close old connection and try to reconnect")
	}
	if ho.conn, err = ho.ConnectServer(ho.addr); err != nil {
		return err
	}
	ho.writer.Reset(ho.conn)
	return nil
}

func (ho *HEPOutputer) ConnectServer(addr string) (conn net.Conn, err error) {
	if config.Cfg.Network == "udp" {
		if ho.conn, err = net.Dial("udp", addr); err != nil {
			return nil, err
		}
	} else if config.Cfg.Network == "tcp" {
		if ho.conn, err = net.Dial("tcp", addr); err != nil {
			return nil, err
		}
	} else if config.Cfg.Network == "tls" {
		if ho.conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("not supported network type %s", config.Cfg.Network)
	}
	return ho.conn, nil
}

func (ho *HEPOutputer) Output(msg []byte) {
	ho.hepQueue <- msg
}

func (ho *HEPOutputer) Send(msg []byte) {
	_, err := ho.writer.Write(msg)
	err = ho.writer.Flush()
	if err != nil {
		ho.errCnt++
		if ho.errCnt%64 == 0 {
			ho.errCnt = 0
			logp.Err("%v", err)
			if err = ho.ReConnect(); err != nil {
				logp.Err("reconnect error: %v", err)
				return
			}
		}
	}
}

func (ho *HEPOutputer) Start() {
	for msg := range ho.hepQueue {
		ho.Send(msg)
	}
}
