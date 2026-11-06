package collector

import (
	"bytes"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/hep"
)

type captureSender struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (c *captureSender) SendNoErr(b []byte) {
	c.mu.Lock()
	c.msgs = append(c.msgs, b)
	c.mu.Unlock()
}

func (c *captureSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func hepPacket(pw string) []byte {
	return hep.Encode(&hep.Msg{Version: 2, Protocol: 17, SrcIP: net.IPv4(1, 2, 3, 4), DstIP: net.IPv4(5, 6, 7, 8),
		ProtoType: 1, NodePW: pw, Payload: []byte("INVITE sip:a SIP/2.0\r\n\r\n")})
}

func startServer(t *testing.T, mut func(*config.Config)) (*Server, *captureSender, int) {
	t.Helper()
	cfg := &config.Config{}
	port := freePort(t)
	cfg.CollectorSettings.Active = true
	cfg.CollectorSettings.Host = "127.0.0.1"
	cfg.CollectorSettings.Port = port
	cfg.CollectorSettings.Proto = "both"
	if mut != nil {
		mut(cfg)
	}
	s := New(cfg)
	snd := &captureSender{}
	s.SetSender(snd)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	time.Sleep(100 * time.Millisecond) // let listeners bind
	return s, snd, port
}

func waitCount(snd *captureSender, want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && snd.count() < want {
		time.Sleep(10 * time.Millisecond)
	}
	return snd.count()
}

func sendUDP(t *testing.T, port int, b []byte) {
	t.Helper()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorAuthToken(t *testing.T) {
	_, snd, port := startServer(t, func(c *config.Config) { c.CollectorSettings.AuthToken = "s3cret" })
	sendUDP(t, port, hepPacket("wrong"))
	sendUDP(t, port, hepPacket(""))
	sendUDP(t, port, hepPacket("s3cret"))
	if got := waitCount(snd, 1); got != 1 {
		t.Fatalf("forwarded %d packets, want only the one with the right token", got)
	}
	time.Sleep(100 * time.Millisecond)
	if snd.count() != 1 {
		t.Fatalf("forwarded %d packets, want 1", snd.count())
	}
}

func TestCollectorAllowList(t *testing.T) {
	_, snd, port := startServer(t, func(c *config.Config) { c.CollectorSettings.AllowedCIDRs = []string{"10.0.0.0/8"} })
	sendUDP(t, port, hepPacket(""))
	time.Sleep(200 * time.Millisecond)
	if snd.count() != 0 {
		t.Fatal("packet from 127.0.0.1 accepted although only 10.0.0.0/8 is allowed")
	}

	_, snd2, port2 := startServer(t, func(c *config.Config) { c.CollectorSettings.AllowedCIDRs = []string{"127.0.0.1"} })
	sendUDP(t, port2, hepPacket(""))
	if waitCount(snd2, 1) != 1 {
		t.Fatal("packet from allowed address not forwarded")
	}
}

func TestCollectorMalformedHEPDoesNotCrash(t *testing.T) {
	_, snd, port := startServer(t, nil)
	sendUDP(t, port, []byte{'H', 'E', 'P', '3', 0, 12, 0, 0, 0, 1, 0, 6})
	sendUDP(t, port, hepPacket(""))
	if waitCount(snd, 1) != 1 {
		t.Fatal("collector stopped forwarding after a malformed packet")
	}
}

func TestCollectorConnectionLimitAndStop(t *testing.T) {
	s, _, port := startServer(t, func(c *config.Config) {
		c.CollectorSettings.Proto = "tcp"
		c.CollectorSettings.MaxConnections = 1
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	time.Sleep(100 * time.Millisecond)
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("second connection over the limit was not closed")
	}

	// c1 is idle and blocked in Read on the server: Stop must still return.
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop hung on an open TCP connection")
	}
}

func TestCollectorHTTP2RejectsOversizedBody(t *testing.T) {
	_, snd, port := startServer(t, func(c *config.Config) { c.CollectorSettings.Proto = "http2" })
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/hep"
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(make([]byte, hep.MaxPacketSize+10)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
	resp, err = http.Post(url, "application/octet-stream", bytes.NewReader(hepPacket("")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || waitCount(snd, 1) != 1 {
		t.Fatalf("valid packet: status %d, forwarded %d", resp.StatusCode, snd.count())
	}
}

func TestReEncodeKeepsExtraChunks(t *testing.T) {
	in := hep.Encode(&hep.Msg{Version: 2, SrcIP: net.IPv4(1, 1, 1, 1), DstIP: net.IPv4(2, 2, 2, 2),
		TCPFlag: 3, IPTos: 4, MOS: 420, Payload: []byte("x")})
	h, err := hep.DecodeHEP(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hep.DecodeHEP(reEncodeWithNewToken(h, "pw", 0, ""))
	if err != nil {
		t.Fatal(err)
	}
	if out.TCPFlag != 3 || out.IPTos != 4 || out.MOS != 420 || out.NodePW != "pw" {
		t.Fatalf("lost chunks on re-encode: %+v", out)
	}
}
