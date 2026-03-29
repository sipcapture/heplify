package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sipcapture/heplify/src/config"
)

type stubConn struct {
	closed   atomic.Bool
	writes   atomic.Int64
	writeErr error
}

type failAfterNConn struct {
	stubConn
	failAfter int64
}

func (s *stubConn) Read(_ []byte) (n int, err error) { return 0, io.EOF }
func (s *stubConn) Write(b []byte) (n int, err error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writes.Add(1)
	return len(b), nil
}
func (s *stubConn) Close() error {
	s.closed.Store(true)
	return nil
}
func (s *stubConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (s *stubConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (s *stubConn) SetDeadline(_ time.Time) error      { return nil }
func (s *stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s *stubConn) SetWriteDeadline(_ time.Time) error { return nil }

func (f *failAfterNConn) Write(b []byte) (int, error) {
	next := f.writes.Add(1)
	if f.failAfter > 0 && next > f.failAfter {
		return 0, errors.New("forced write failure")
	}
	return len(b), nil
}

type testTCPServer struct {
	listener     net.Listener
	mu           sync.Mutex
	currentConn  net.Conn
	acceptCount  int
	messageCount int
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func newTestTCPServer(t *testing.T) *testTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test tcp server: %v", err)
	}
	s := &testTCPServer{
		listener: ln,
		stopCh:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *testTCPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}
		s.mu.Lock()
		s.acceptCount++
		s.currentConn = conn
		s.mu.Unlock()
		s.wg.Add(1)
		go s.readLoop(conn)
	}
}

func (s *testTCPServer) readLoop(conn net.Conn) {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				_ = conn.Close()
			}
			return
		}
		s.mu.Lock()
		s.messageCount++
		s.mu.Unlock()
	}
}

func (s *testTCPServer) addr() string {
	return s.listener.Addr().String()
}

func (s *testTCPServer) closeCurrentConn() {
	s.mu.Lock()
	conn := s.currentConn
	s.currentConn = nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *testTCPServer) snapshot() (acceptCount int, messageCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptCount, s.messageCount
}

func (s *testTCPServer) close() {
	close(s.stopCh)
	_ = s.listener.Close()
	s.closeCurrentConn()
	s.wg.Wait()
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for condition: %s", msg)
}

func TestSenderReconnectTCP(t *testing.T) {
	server := newTestTCPServer(t)
	defer server.close()

	host, portStr, err := net.SplitHostPort(server.addr())
	if err != nil {
		t.Fatalf("bad server addr: %v", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatalf("bad server port: %v", err)
	}

	cfg := &config.Config{}
	cfg.TransportSettings = []config.TransportSettings{
		{
			Name:      "test-tcp",
			Active:    true,
			Protocol:  "HEPv3",
			Host:      host,
			Port:      port,
			Transport: "tcp",
		},
	}

	sender := New(cfg)
	defer sender.Close()

	client := sender.clients[0].hep

	waitFor(t, 5*time.Second, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.state == stateConnected && client.conn != nil
	}, "initial tcp connect")

	if err := sender.Send([]byte("first")); err != nil {
		t.Fatalf("failed to queue first message: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool {
		_, msgCount := server.snapshot()
		return msgCount >= 1
	}, "first message delivered")

	server.closeCurrentConn()

	for i := 0; i < 20; i++ {
		_ = sender.Send([]byte("after-disconnect"))
		time.Sleep(100 * time.Millisecond)
		client.mu.Lock()
		st := client.state
		client.mu.Unlock()
		if st == stateReconnecting || st == stateConnecting {
			break
		}
	}

	waitFor(t, 12*time.Second, func() bool {
		client.mu.Lock()
		connected := client.state == stateConnected && client.conn != nil
		client.mu.Unlock()
		acceptCount, _ := server.snapshot()
		return connected && acceptCount >= 2
	}, "tcp reconnected")

	if err := sender.Send([]byte("second")); err != nil {
		t.Fatalf("failed to queue second message: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool {
		_, msgCount := server.snapshot()
		return msgCount >= 2
	}, "message delivered after reconnect")
}

func TestHandleWriteErrorDoesNotCloseNewConn(t *testing.T) {
	cfg := &config.Config{}
	sender := New(cfg)
	defer sender.Close()

	oldConn := &stubConn{writeErr: errors.New("old conn failed")}
	newConn := &stubConn{}
	client := &HEPClient{
		addr:         "127.0.0.1:0",
		proto:        "tcp",
		conn:         newConn,
		state:        stateConnected,
		backoff:      initialReconnectBackoff,
		reconnecting: true,
	}

	sender.handleWriteError(client, oldConn, errors.New("stale write error"))

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.conn != newConn {
		t.Fatalf("stale error should not replace current conn")
	}
	if newConn.closed.Load() {
		t.Fatalf("stale error should not close new conn")
	}
}

func TestDrainBufferSingleWorker(t *testing.T) {
	tmpDir := t.TempDir()
	bufferFile := filepath.Join(tmpDir, "hep-buffer.dump")

	cfg := &config.Config{}
	cfg.BufferSettings.Enable = true
	cfg.BufferSettings.File = bufferFile
	sender := New(cfg)
	defer sender.Close()

	payload := []byte("msg-one")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if err := os.WriteFile(bufferFile, append(lenBuf, payload...), 0600); err != nil {
		t.Fatalf("failed to write buffer file: %v", err)
	}

	conn := &stubConn{}
	client := &HEPClient{
		addr:    "127.0.0.1:0",
		proto:   "tcp",
		conn:    conn,
		state:   stateConnected,
		backoff: initialReconnectBackoff,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sender.drainBuffer(client)
	}()
	go func() {
		defer wg.Done()
		sender.drainBuffer(client)
	}()
	wg.Wait()

	if got := conn.writes.Load(); got != 1 {
		t.Fatalf("expected exactly one buffered write, got %d", got)
	}
}

func TestSendAfterCloseReturnsError(t *testing.T) {
	cfg := &config.Config{}
	sender := New(cfg)
	sender.Close()

	if err := sender.Send([]byte("after-close")); err == nil {
		t.Fatalf("expected error when sending after Close")
	}
}

func TestCloseDrainsInFlightQueue(t *testing.T) {
	tmpDir := t.TempDir()
	bufferFile := filepath.Join(tmpDir, "close-drain.dump")

	cfg := &config.Config{}
	cfg.TransportSettings = []config.TransportSettings{
		{
			Name:      "test-tcp-close",
			Active:    true,
			Protocol:  "HEPv3",
			Host:      "127.0.0.1",
			Port:      1,
			Transport: "tcp",
		},
	}
	cfg.BufferSettings.Enable = true
	cfg.BufferSettings.File = bufferFile
	sender := New(cfg)

	for i := 0; i < 100; i++ {
		_ = sender.Send([]byte("queued-before-close"))
	}

	done := make(chan struct{})
	go func() {
		sender.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sender.Close timed out while draining queue")
	}

	if got := len(sender.hepQueue); got != 0 {
		t.Fatalf("expected queue to be drained on close, got %d messages", got)
	}
}

func TestDrainBufferKeepsTailOnPartialSend(t *testing.T) {
	tmpDir := t.TempDir()
	bufferFile := filepath.Join(tmpDir, "hep-buffer.dump")

	cfg := &config.Config{}
	cfg.BufferSettings.Enable = true
	cfg.BufferSettings.File = bufferFile
	sender := New(cfg)
	defer sender.Close()

	msg1 := []byte("first")
	msg2 := []byte("second")
	fileData := make([]byte, 0)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(msg1)))
	fileData = append(fileData, lenBuf...)
	fileData = append(fileData, msg1...)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(msg2)))
	fileData = append(fileData, lenBuf...)
	fileData = append(fileData, msg2...)
	if err := os.WriteFile(bufferFile, fileData, 0600); err != nil {
		t.Fatalf("failed to write buffer file: %v", err)
	}

	conn := &failAfterNConn{failAfter: 1}
	client := &HEPClient{
		addr:         "127.0.0.1:0",
		proto:        "tcp",
		conn:         conn,
		state:        stateConnected,
		backoff:      initialReconnectBackoff,
		reconnecting: true, // avoid starting reconnect goroutine in this unit check
	}

	sender.drainBuffer(client)

	remaining, err := os.ReadFile(bufferFile)
	if err != nil {
		t.Fatalf("failed to read remaining buffer: %v", err)
	}
	if len(remaining) >= len(fileData) {
		t.Fatalf("expected partial drain, got full data size still present")
	}
}
