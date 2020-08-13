package publish

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
)

type HEPConn struct {
	conn   net.Conn
	writer *bufio.Writer
	errCnt uint
}
type HEPOutputer struct {
	hepQueue chan []byte
	addr     []string
	client   []HEPConn
}

func NewHEPOutputer(serverAddr string) (*HEPOutputer, error) {
	a := strings.Split(cutSpace(serverAddr), ",")
	l := len(a)
	h := &HEPOutputer{
		addr:     a,
		client:   make([]HEPConn, l),
		hepQueue: make(chan []byte, 20000),
	}
	errCnt := 0
	for n := range a {
		if err := h.ConnectServer(n); err != nil {
			logp.Err("%v", err)
			errCnt++
		}
	}
	if errCnt == l {
		return nil, fmt.Errorf("cannot establish a connection")
	}

	go h.Start()
	return h, nil
}

func (h *HEPOutputer) Close(n int) {
	if err := h.client[n].conn.Close(); err != nil {
		logp.Err("cannnot close connection to %s: %v", h.addr[n], err)
	}
}

func (h *HEPOutputer) ReConnect(n int) (err error) {
	if err = h.ConnectServer(n); err != nil {
		return err
	}
	h.client[n].writer.Reset(h.client[n].conn)
	return err
}

func (h *HEPOutputer) ConnectServer(n int) (err error) {
	if config.Cfg.Network == "udp" {
		if h.client[n].conn, err = net.Dial("udp", h.addr[n]); err != nil {
			return err
		}
	} else if config.Cfg.Network == "tcp" {
		if h.client[n].conn, err = net.Dial("tcp", h.addr[n]); err != nil {
			return err
		}
	} else if config.Cfg.Network == "tls" {
		if h.client[n].conn, err = tls.Dial("tcp", h.addr[n], &tls.Config{InsecureSkipVerify: true}); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("not supported network type %s", config.Cfg.Network)
	}
	h.client[n].writer = bufio.NewWriterSize(h.client[n].conn, 8192)
	return err
}

func (h *HEPOutputer) Output(msg []byte) {
	h.hepQueue <- msg
}

func (h *HEPOutputer) Send(msg []byte) {
	for n := range h.addr {
		h.client[n].writer.Write(msg)
		err := h.client[n].writer.Flush()
		if err != nil {
			logp.Err("%v", err)
			h.client[n].errCnt++
			var retry bool
			if config.Cfg.SendRetries > 0 {
				retry = (h.client[n].errCnt % config.Cfg.SendRetries) == 0
			} else {
				retry = true
			}
			if retry {
				h.client[n].errCnt = 0
				if err = h.ReConnect(n); err != nil {
					logp.Err("reconnect error: %v", err)
					return
				}
			}
		}
	}
}

func (h *HEPOutputer) Start() {
	for msg := range h.hepQueue {
		h.Send(msg)
	}
}

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
