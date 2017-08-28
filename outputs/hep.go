package outputs

import (
	"net"

	"github.com/negbie/heplify/logp"
)

type Outputer interface {
	Output(msg []byte)
}

type HepOutputer struct {
	Addr     string
	Conn     net.Conn
	hepQueue chan []byte
}

func NewHepOutputer(serverAddr string) (*HepOutputer, error) {
	so := &HepOutputer{
		Addr:     serverAddr,
		hepQueue: make(chan []byte, 1024),
	}
	err := so.Init()
	if err != nil {
		return nil, err
	}
	go so.Start()
	return so, nil
}

func (ho *HepOutputer) Init() error {
	conn, err := ho.ConnectServer(ho.Addr)
	if err != nil {
		logp.Err("hepOutputer server connection error: %v", err)
		return err
	}
	ho.Conn = conn
	return nil
}

func (ho *HepOutputer) Close() {
	logp.Info("hepOutputer connection close.")
	ho.Conn.Close()
}

func (ho *HepOutputer) ReConnect() error {
	logp.Warn("reconnect server.")
	conn, err := ho.ConnectServer(ho.Addr)
	if err != nil {
		logp.Err("reconnect server error: %v", err)
		return err
	}
	ho.Conn = conn
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
	logp.Info("pkt %s", msg)
}

func (ho *HepOutputer) Send(msg []byte) {

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
			if counter%1024 == 0 {
				logp.Debug("hep", "Packet number: %d", counter)
			}
		}
	}
}
