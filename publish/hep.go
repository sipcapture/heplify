package publish

import (
	"bufio"
	"net"

	"github.com/negbie/heplify/logp"
)

type HEPOutputer struct {
	addr     string
	writer   *bufio.Writer
	hepQueue chan []byte
}

func NewHEPOutputer(serverAddr string) (*HEPOutputer, error) {
	ho := &HEPOutputer{
		addr:     serverAddr,
		hepQueue: make(chan []byte, 10000),
	}
	err := ho.Init()
	if err != nil {
		return nil, err
	}
	go ho.Start()
	return ho, nil
}

func (ho *HEPOutputer) Init() error {
	conn, err := ho.ConnectServer(ho.addr)
	if err != nil {
		logp.Err("server connection error: %v", err)
		return err
	}
	w := bufio.NewWriter(conn)
	ho.writer = w
	return nil
}

func (ho *HEPOutputer) Close() {
	logp.Info("connection close.")
}

func (ho *HEPOutputer) ReConnect() error {
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

func (ho *HEPOutputer) ConnectServer(addr string) (conn net.Conn, err error) {
	conn, err = net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (ho *HEPOutputer) Output(msg []byte) {
	ho.hepQueue <- msg
}

func (ho *HEPOutputer) Send(msg []byte) {
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
