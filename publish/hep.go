package publish

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"time"
	"unicode"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/promstats"
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
	msgPing  []byte
}

func writeAndFlush(client *HEPConn, data []byte, action string) (int, error) {
	hl, err := client.conn.Write(data)
	if err != nil {
		promstats.HepFileFlushesError.Inc()
		return 0, fmt.Errorf("error writing to socket during %s: %w", action, err)
	}

	if err := client.writer.Flush(); err != nil {
		promstats.HepFileFlushesError.Inc()
		return 0, fmt.Errorf("error flushing writer during %s: %w", action, err)
	}

	return hl, nil
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
			logp.Err("Error connecting to HEP server (%s): %v", h.addr[n], err)
			errCnt++
		} else {
			if config.Cfg.HEPBufferEnable {
				logp.Debug("collector", "send ping packet after disconnect")
				h.client[n].writer.Write(h.msgPing)
				err = h.client[n].writer.Flush()
				if _, err := os.Stat(config.Cfg.HEPBufferFile); err == nil {
					if _, err := h.copyHEPFileOut(n); err != nil {
						logp.Err("Sending HEP from file error: %v", err)
					}
				}
			}
		}
	}
	if errCnt == l {
		return nil, fmt.Errorf("Cannot establish a connection")
	}

	go h.Start()
	return h, nil
}

func (h *HEPOutputer) Close(n int) {
	if err := h.client[n].conn.Close(); err != nil {
		logp.Err("Cannot close connection to %s: %v", h.addr[n], err)
	}
}

func (h *HEPOutputer) ReConnect(n int) (err error) {
	if err = h.ConnectServer(n); err != nil {
		logp.Err("Error reconnecting to HEP server (%s): %v", h.addr[n], err)
		return err
	}
	h.client[n].writer.Reset(h.client[n].conn)

	//send ping packet on reconnect
	h.ReSendPingPacket()

	if config.Cfg.HEPBufferEnable {
		if _, err := h.copyHEPFileOut(n); err != nil {
			logp.Err("Sending HEP from file error: %v", err)
		}
	}

	return err
}

func (h *HEPOutputer) ConnectServer(n int) (err error) {
	if config.Cfg.Network == "udp" {
		if h.client[n].conn, err = net.Dial("udp", h.addr[n]); err != nil {
			promstats.ConnectionStatus.Set(0)
			return err
		}
	} else if config.Cfg.Network == "tcp" {
		if h.client[n].conn, err = net.Dial("tcp", h.addr[n]); err != nil {
			promstats.ConnectionStatus.Set(0)
			return err
		}
	} else if config.Cfg.Network == "tls" {
		if h.client[n].conn, err = tls.Dial("tcp", h.addr[n], &tls.Config{InsecureSkipVerify: config.Cfg.SkipVerify}); err != nil {
			promstats.ConnectionStatus.Set(0)
			return err
		}
	} else {
		promstats.ConnectionStatus.Set(0)
		return fmt.Errorf("not supported network type %s", config.Cfg.Network)
	}

	promstats.ConnectionStatus.Set(1)
	h.client[n].writer = bufio.NewWriterSize(h.client[n].conn, 8192)

	//Tcp Keep Alive
	if config.Cfg.Network == "tcp" || config.Cfg.Network == "tls" {
		// Keep Alive
		if config.Cfg.KeepAlive > 0 {

			var tcpCon *net.TCPConn
			if config.Cfg.Network == "tls" {
				tcpCon = h.client[n].conn.(*tls.Conn).NetConn().(*net.TCPConn)
			} else {
				tcpCon = h.client[n].conn.(*net.TCPConn)
			}

			tcpCon.SetKeepAlive(true)
			tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(config.Cfg.KeepAlive))
		}
	}

	return err
}

func (h *HEPOutputer) Output(msg []byte) {
	h.hepQueue <- msg
}

func (h *HEPOutputer) SendPingPacket(msg []byte) {

	if h.msgPing == nil {
		h.msgPing = make([]byte, len(msg))
	}

	copy(h.msgPing, msg)

	h.hepQueue <- h.msgPing
}

func (h *HEPOutputer) ReSendPingPacket() {

	if h.msgPing != nil {
		logp.Debug("collector", "send ping packet")
		h.hepQueue <- h.msgPing
	}
}

func (h *HEPOutputer) Send(msg []byte) {
	onceSent := false
	for n := range h.addr {

		var err error

		if h.client[n].conn == nil || h.client[n].writer == nil {
			logp.Debug("Connection is not up", fmt.Sprintf("index: %d, Len: %d, once: %v", n, len(h.addr), onceSent))
			err = fmt.Errorf("connection is broken")
		} else {
			h.client[n].writer.Write(msg)
			err = h.client[n].writer.Flush()
		}

		if err != nil {
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
					if config.Cfg.HEPBufferEnable && (!onceSent && n == (len(h.addr)-1)) {
						h.copyHEPbufftoFile(msg)
					}
				} else {
					if h.msgPing != nil {
						logp.Debug("collector", "send ping packet after disconnect")
						h.client[n].writer.Write(h.msgPing)
						err = h.client[n].writer.Flush()
						if err != nil {
							logp.Err("Bad during resend ping packet : %v", err)
						}
					}

					_, err := writeAndFlush(&h.client[n], msg, "Bad resend")
					if err != nil {
						logp.Err(err.Error())
						if config.Cfg.HEPBufferEnable && (!onceSent && n == (len(h.addr)-1)) {
							h.copyHEPbufftoFile(msg)
						}
					}
				}
			} else {
				if config.Cfg.HEPBufferEnable && (!onceSent && n == (len(h.addr)-1)) {
					h.copyHEPbufftoFile(msg)
				}
			}
		} else {
			onceSent = true
		}
	}
}

func (h *HEPOutputer) Start() {
	for msg := range h.hepQueue {
		h.Send(msg)
	}
}

func (h *HEPOutputer) copyHEPFileOut(n int) (int, error) {

	defer func() {
		if r := recover(); r != nil {
			logp.Err("Copy hep file out panic: %v, %v", r, debug.Stack())
			return
		}
	}()

	if _, err := os.Stat(config.Cfg.HEPBufferFile); err != nil {
		logp.Debug("File doesn't exists: ", config.Cfg.HEPBufferFile)
		return 1, nil
	}

	HEPFileData, HEPFileDataerr := os.ReadFile(config.Cfg.HEPBufferFile)
	if HEPFileDataerr != nil {
		logp.Err("Read HEP file error: %v", HEPFileDataerr)
		return 0, fmt.Errorf("bad read file")
	}

	if h.client[n].conn == nil {
		logp.Err("Connection is not up....")
		return 0, fmt.Errorf("Connection is broken")
	}

	hl, err := writeAndFlush(&h.client[n], h.msgPing, "ping operation")
	if err != nil {
		return 0, err
	}

	// Send Logged HEP upon reconnect
	hl, err = writeAndFlush(&h.client[n], HEPFileData, "HEP reconnect")
	if err != nil {
		return 0, err
	}

	err = h.client[n].writer.Flush()
	if err != nil {
		logp.Debug("collector", " ||-->X Send HEP from LOG error ", err)
	} else {

		fi, err := os.Stat(config.Cfg.HEPBufferFile)
		if err != nil {
			logp.Debug("collector", " Cannot stat HEP log file ", err)
		}
		if fi.Size() > 0 {
			logp.Debug("collector", " Send HEP from LOG OK: ", hl, " bytes")
			promstats.HepFileFlushesSuccess.Inc()
			//Recreate file, thus cleaning the content
			os.Create(config.Cfg.HEPBufferFile)
		}
	}

	return hl, err
}

func (h *HEPOutputer) copyHEPbufftoFile(inbytes []byte) (int64, error) {

	defer func() {
		if r := recover(); r != nil {
			logp.Err("Copy buffer to panic: %v,\n%s", r, debug.Stack())
			return
		}
	}()

	if config.Cfg.HEPBufferDebug {
		logp.Err("Adding packet to BUFFER: %s\n", string(inbytes))
	}

	destination, err := os.OpenFile(config.Cfg.HEPBufferFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logp.Err("Open HEP file error: %v\n", err)
		return 0, fmt.Errorf("Open HEP file error: %v", err)
	}

	defer destination.Close()

	if config.Cfg.MaxBufferSizeBytes > 0 {
		fi, err := destination.Stat()
		if err != nil {
			logp.Debug("collector", fmt.Sprintf("Couldn't retrive stats from buffer file error: %v", err.Error()))
			return 0, err
		} else {
			if fi.Size() >= config.Cfg.MaxBufferSizeBytes {
				logp.Debug("collector", fmt.Sprintln("Buffer size has been exceeded error: Maxsize: ", config.Cfg.MaxBufferSizeBytes, " vs CurrentSize: ", fi.Size()))
				return 0, fmt.Errorf("Buffer size has been exceeded: %d", fi.Size())
			}
		}
	}

	nBytes, err := destination.Write(inbytes)

	if err != nil {
		logp.Err("File send HEP from buffer to file error: %v", err.Error())
		return 0, fmt.Errorf("file Send HEP from buffer to file error: %v", err.Error())
	} else {
		logp.Debug("collector", " File Send HEP from buffer to file OK")
	}

	go promstats.HepBytesInFile.Add(float64(nBytes))

	return int64(nBytes), err
}

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
