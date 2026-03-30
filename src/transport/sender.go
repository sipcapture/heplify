package transport

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/apiserver"
	"github.com/sipcapture/heplify/src/config"
)

type clientState string

const (
	stateDisconnected clientState = "disconnected"
	stateConnecting   clientState = "connecting"
	stateConnected    clientState = "connected"
	stateReconnecting clientState = "reconnecting"

	initialReconnectBackoff = time.Second
	maxReconnectBackoff     = 30 * time.Second
	maxDrainBatchMessages   = 1000
)

// clientKind identifies the underlying transport type.
type clientKind int

const (
	kindHEP    clientKind = iota
	kindFlight clientKind = iota
)

// transportClient is the internal union of HEP and Arrow Flight connections.
// A Sender holds a slice of these and dispatches accordingly.
type transportClient struct {
	kind         clientKind
	failoverOnly bool               // if true: use only when all primary transports fail
	hep          *HEPClient         // non-nil when kind == kindHEP
	flight       *ArrowFlightClient // non-nil when kind == kindFlight
}

// HEPClient represents a single HEP server connection
type HEPClient struct {
	addr         string
	proto        string
	skipVerify   bool
	keepAlive    int
	payloadZip   bool
	maxRetries   int // 0 = unlimited
	conn         net.Conn
	errCnt       uint
	state        clientState
	reconnecting bool
	backoff      time.Duration
	mu           sync.Mutex
}

// Sender manages multiple HEP server connections and/or Arrow Flight clients.
type Sender struct {
	cfg             *config.Config
	clients         []*transportClient
	hepQueue        chan []byte
	bufferFile      string
	bufferMaxSize   int64
	bufferEnabled   bool
	bufferDebug     bool
	mu              sync.RWMutex
	closed          atomic.Bool
	stopCh          chan struct{}
	drainInProgress atomic.Bool
	workerWG        sync.WaitGroup
	reconnectWG     sync.WaitGroup
}

// New creates a new Sender with connections to all active transports in cfg.
func New(cfg *config.Config) *Sender {
	return NewFromTransports(cfg.TransportSettings, cfg)
}

// NewFromTransports creates a Sender using only the provided transport list.
// Buffer and queue settings are taken from cfg. Transports that are not Active
// in the provided list are skipped.
func NewFromTransports(transports []config.TransportSettings, cfg *config.Config) *Sender {
	bufferFile := cfg.BufferSettings.File
	if bufferFile == "" {
		bufferFile = "hep-buffer.dump"
	}

	bufferMaxSize := cfg.BufferSettings.MaxSizeBytes
	if bufferMaxSize == 0 {
		bufferMaxSize = 100 * 1024 * 1024 // 100 MB default
	}

	s := &Sender{
		cfg:           cfg,
		clients:       make([]*transportClient, 0),
		hepQueue:      make(chan []byte, 20000),
		bufferFile:    bufferFile,
		bufferMaxSize: bufferMaxSize,
		bufferEnabled: cfg.BufferSettings.Enable,
		bufferDebug:   cfg.BufferSettings.Debug,
		stopCh:        make(chan struct{}),
	}

	for _, t := range transports {
		if !t.Active {
			continue
		}

		if strings.ToLower(t.Transport) == "grpc-flight" {
			fc, err := newArrowFlightClient(t)
			if err != nil {
				log.Error().
					Str("component", "sender").
					Str("addr", fmt.Sprintf("%s:%d", t.Host, t.Port)).
					Err(err).
					Msg("Failed to create Arrow Flight client")
				continue
			}
			s.clients = append(s.clients, &transportClient{kind: kindFlight, failoverOnly: t.FailoverOnly, flight: fc})
			continue
		}

		proto := t.Transport
		if proto == "" {
			proto = "udp"
		}

		hc := &HEPClient{
			addr:       fmt.Sprintf("%s:%d", t.Host, t.Port),
			proto:      proto,
			skipVerify: t.SkipVerify,
			keepAlive:  t.KeepAlive,
			payloadZip: t.PayloadZip,
			maxRetries: t.MaxRetries,
			state:      stateDisconnected,
			backoff:    initialReconnectBackoff,
		}
		s.clients = append(s.clients, &transportClient{kind: kindHEP, failoverOnly: t.FailoverOnly, hep: hc})
	}

	// Connect to all HEP servers
	for _, tc := range s.clients {
		if tc.kind == kindHEP {
			s.scheduleReconnect(tc.hep, "initial connect")
		}
	}

	// Start the send worker
	s.workerWG.Add(1)
	go s.startWorker()

	return s
}

func (s *Sender) dial(client *HEPClient) (net.Conn, error) {
	switch client.proto {
	case "udp":
		return net.Dial("udp", client.addr)
	case "tcp":
		conn, err := net.Dial("tcp", client.addr)
		if err != nil {
			return nil, err
		}
		if client.keepAlive > 0 {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(time.Duration(client.keepAlive) * time.Second)
			}
		}
		return conn, nil
	case "tls":
		if client.skipVerify {
			log.Warn().Str("addr", client.addr).Msg("TLS skip_verify is enabled; certificate verification is disabled")
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: client.skipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		tlsConn, err := tls.Dial("tcp", client.addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		if client.keepAlive > 0 {
			if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(time.Duration(client.keepAlive) * time.Second)
			}
		}
		return tlsConn, nil
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", client.proto)
	}
}

func (s *Sender) scheduleReconnect(client *HEPClient, reason string) {
	if s.closed.Load() {
		return
	}

	client.mu.Lock()
	if client.reconnecting {
		client.mu.Unlock()
		return
	}
	client.reconnecting = true
	client.state = stateReconnecting
	client.mu.Unlock()

	apiserver.IncReconnect(client.addr, client.proto)
	s.reconnectWG.Add(1)
	go s.reconnectLoop(client, reason)
}

func (s *Sender) reconnectLoop(client *HEPClient, reason string) {
	defer s.reconnectWG.Done()
	for {
		if s.closed.Load() {
			client.mu.Lock()
			client.reconnecting = false
			client.mu.Unlock()
			return
		}

		client.mu.Lock()
		client.state = stateConnecting
		client.mu.Unlock()

		conn, err := s.dial(client)
		if err == nil {
			client.mu.Lock()
			client.conn = conn
			client.errCnt = 0
			client.state = stateConnected
			client.reconnecting = false
			client.backoff = initialReconnectBackoff
			client.mu.Unlock()
			apiserver.SetTransportConnected(client.addr, client.proto, true)

			log.Info().
				Str("component", "sender").
				Str("addr", client.addr).
				Str("transport", client.proto).
				Str("reason", reason).
				Msg("Connected to HEP server")

			// Try to drain buffer after successful connection.
			go s.drainBuffer(client)
			return
		}

		client.mu.Lock()
		client.errCnt++
		backoff := client.backoff
		if backoff <= 0 {
			backoff = initialReconnectBackoff
		}
		nextBackoff := backoff * 2
		if nextBackoff > maxReconnectBackoff {
			nextBackoff = maxReconnectBackoff
		}
		client.backoff = nextBackoff
		client.state = stateReconnecting
		reachedLimit := client.maxRetries > 0 && int(client.errCnt) >= client.maxRetries
		client.mu.Unlock()
		apiserver.SetTransportConnected(client.addr, client.proto, false)

		if reachedLimit {
			log.Error().
				Str("component", "sender").
				Str("addr", client.addr).
				Str("transport", client.proto).
				Int("max_retries", client.maxRetries).
				Msg("Reached max reconnect attempts, giving up")
			client.mu.Lock()
			client.state = stateDisconnected
			client.reconnecting = false
			client.mu.Unlock()
			return
		}

		log.Error().
			Str("component", "sender").
			Err(err).
			Str("transport", client.proto).
			Str("addr", client.addr).
			Str("reason", reason).
			Dur("retry_in", backoff).
			Msg("Failed to connect to HEP server")

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-s.stopCh:
			timer.Stop()
			client.mu.Lock()
			client.reconnecting = false
			client.mu.Unlock()
			return
		}
	}
}

func (s *Sender) handleWriteError(client *HEPClient, failedConn net.Conn, err error) {
	log.Error().
		Str("component", "sender").
		Str("transport", client.proto).
		Str("addr", client.addr).
		Str("reason", "write error").
		Err(err).
		Msg("Failed to send HEP")
	client.mu.Lock()
	if client.conn == failedConn && client.conn != nil {
		_ = client.conn.Close()
		client.conn = nil
		client.state = stateDisconnected
		client.errCnt++
		apiserver.SetTransportConnected(client.addr, client.proto, false)
	}
	client.mu.Unlock()

	s.scheduleReconnect(client, "write error")
}

// startWorker processes the HEP queue
func (s *Sender) startWorker() {
	defer s.workerWG.Done()
	for {
		select {
		case <-s.stopCh:
			// Drain remaining in-memory queue before exit.
			for {
				select {
				case msg := <-s.hepQueue:
					s.sendToAll(msg)
				default:
					apiserver.SetQueueSize(len(s.hepQueue))
					return
				}
			}
		case msg := <-s.hepQueue:
			s.sendToAll(msg)
			apiserver.SetQueueSize(len(s.hepQueue))
		}
	}
}

// sendToAll sends raw HEP bytes to all connected HEP servers.
// Delivery follows a two-phase priority model:
//   - Phase 1 (primary): send to all non-failover transports.
//   - Phase 2 (backup):  if no primary succeeded, send to failover-only transports.
//
// Arrow Flight clients are skipped here — they receive structured data via SendRecord.
func (s *Sender) sendToAll(msg []byte) {
	primarySent := s.sendToGroup(msg, false)
	if !primarySent {
		backupSent := s.sendToGroup(msg, true)
		if !backupSent {
			s.bufferToFile(msg)
			apiserver.IncTransportError("", "")
		}
	}
}

// sendToGroup sends msg to all connected HEP transports that match the failoverOnly flag.
// Returns true if at least one send succeeded.
func (s *Sender) sendToGroup(msg []byte, failoverOnly bool) bool {
	sent := false
	hasClients := false

	for _, tc := range s.clients {
		if tc.kind != kindHEP || tc.failoverOnly != failoverOnly {
			continue
		}
		hasClients = true
		client := tc.hep

		client.mu.Lock()
		if client.conn == nil {
			client.mu.Unlock()
			s.scheduleReconnect(client, "connection is nil")
			continue
		}

		conn := client.conn
		state := client.state
		payloadZip := client.payloadZip
		client.mu.Unlock()

		if state != stateConnected {
			s.scheduleReconnect(client, "client not connected")
			continue
		}

		data := msg
		if payloadZip {
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			if _, err := gz.Write(msg); err == nil {
				gz.Close()
				data = b.Bytes()
			} else {
				gz.Close()
			}
		}

		n, err := conn.Write(data)
		if err != nil {
			s.handleWriteError(client, conn, err)
			if !sent {
				s.bufferToFile(msg)
			}
			continue
		}

		log.Debug().
			Str("addr", client.addr).
			Str("transport", client.proto).
			Bool("failover", failoverOnly).
			Int("bytes", n).
			Msg("HEP packet sent")

		client.mu.Lock()
		client.errCnt = 0
		client.state = stateConnected
		client.backoff = initialReconnectBackoff
		client.mu.Unlock()
		sent = true
		apiserver.IncTransportSent(client.addr, client.proto)
	}

	// No clients of this tier configured — treat as "no attempt needed".
	if !hasClients {
		return false
	}
	return sent
}

// SendRecord dispatches a structured PacketRecord to all Arrow Flight clients.
// HEP clients are skipped — they only receive raw bytes via Send().
func (s *Sender) SendRecord(r PacketRecord) {
	for _, tc := range s.clients {
		if tc.kind == kindFlight {
			tc.flight.AddRecord(r)
		}
	}
}

// HasFlightClients returns true if any active transport is grpc-flight.
func (s *Sender) HasFlightClients() bool {
	for _, tc := range s.clients {
		if tc.kind == kindFlight {
			return true
		}
	}
	return false
}

// Send queues a message for sending to all servers
func (s *Sender) Send(data []byte) error {
	if s.closed.Load() {
		apiserver.HepErrorCount.Inc()
		return fmt.Errorf("sender is closed")
	}
	select {
	case <-s.stopCh:
		apiserver.HepErrorCount.Inc()
		apiserver.HepDroppedCount.Inc()
		return fmt.Errorf("sender is stopping")
	case s.hepQueue <- data:
		apiserver.SetQueueSize(len(s.hepQueue))
		return nil
	default:
		apiserver.HepErrorCount.Inc()
		apiserver.HepDroppedCount.Inc()
		return fmt.Errorf("HEP queue is full")
	}
}

// bufferToFile writes HEP data to disk when all servers are unavailable
func (s *Sender) bufferToFile(data []byte) {
	if !s.bufferEnabled {
		apiserver.HepDroppedCount.Inc()
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.bufferFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error().Str("component", "sender").Err(err).Msg("Failed to open buffer file")
		return
	}
	defer f.Close()

	// Check file size limit
	if s.bufferMaxSize > 0 {
		fi, err := f.Stat()
		if err != nil {
			log.Debug().Str("component", "sender").Err(err).Msg("Failed to stat buffer file")
		} else if fi.Size() >= s.bufferMaxSize {
			log.Warn().
				Str("component", "sender").
				Int64("current_size", fi.Size()).
				Int64("max_size", s.bufferMaxSize).
				Msg("Buffer file size limit exceeded, dropping packet")
			apiserver.HepDroppedCount.Inc()
			return
		}
	}

	if s.bufferDebug {
		log.Debug().Str("component", "sender").Int("size", len(data)).Msg("Buffering HEP packet to file")
	}

	// Write length-prefixed data for proper parsing later
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := f.Write(lenBuf); err != nil {
		log.Error().Str("component", "sender").Err(err).Msg("Failed to write length to buffer")
		return
	}
	if _, err := f.Write(data); err != nil {
		log.Error().Str("component", "sender").Err(err).Msg("Failed to write data to buffer")
	}
	if fi, err := f.Stat(); err == nil {
		apiserver.SetBufferSizeBytes(fi.Size())
	}
}

// drainBuffer reads buffered HEP data and sends it
func (s *Sender) drainBuffer(client *HEPClient) {
	if !s.drainInProgress.CompareAndSwap(false, true) {
		return
	}
	defer s.drainInProgress.Store(false)

	// Check if buffer file exists
	if _, err := os.Stat(s.bufferFile); os.IsNotExist(err) {
		return
	}

	s.mu.Lock()
	data, err := os.ReadFile(s.bufferFile)
	s.mu.Unlock()
	if err != nil {
		log.Error().Str("component", "sender").Err(err).Msg("Failed to read buffer file")
		return
	}

	if len(data) == 0 {
		return
	}

	// Parse and send length-prefixed messages
	offset := 0
	sentCount := 0
	bytesConsumed := 0
	for offset+4 <= len(data) {
		if sentCount >= maxDrainBatchMessages {
			break
		}

		msgLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(msgLen) > len(data) {
			break
		}

		msg := data[offset : offset+int(msgLen)]
		offset += int(msgLen)

		client.mu.Lock()
		conn := client.conn
		if conn == nil {
			client.mu.Unlock()
			break
		}
		_, err := conn.Write(msg)
		client.mu.Unlock()
		if err != nil {
			log.Error().Str("component", "sender").Err(err).Str("reason", "buffer drain write").Msg("Failed to send buffered HEP")
			s.handleWriteError(client, conn, err)
			break
		}
		sentCount++
		bytesConsumed = offset
	}

	if sentCount > 0 {
		log.Info().
			Str("component", "sender").
			Str("transport", client.proto).
			Str("addr", client.addr).
			Int("count", sentCount).
			Int("remaining_bytes", len(data)-bytesConsumed).
			Msg("Sent buffered HEP messages")
		s.mu.Lock()
		defer s.mu.Unlock()
		if bytesConsumed >= len(data) {
			_ = os.Truncate(s.bufferFile, 0)
			apiserver.SetBufferSizeBytes(0)
			return
		}
		remaining := data[bytesConsumed:]
		tmpFile := s.bufferFile + ".tmp"
		if err := os.WriteFile(tmpFile, remaining, 0600); err != nil {
			log.Error().Str("component", "sender").Err(err).Msg("Failed to write temporary drain file")
			return
		}
		if err := os.Rename(tmpFile, s.bufferFile); err != nil {
			log.Error().Str("component", "sender").Err(err).Msg("Failed to atomically replace buffer file")
			return
		}
		apiserver.SetBufferSizeBytes(int64(len(remaining)))
	}
}

// Close closes all connections
func (s *Sender) Close() {
	if s.closed.Swap(true) {
		return
	}
	close(s.stopCh)
	s.workerWG.Wait()
	s.reconnectWG.Wait()
	for _, tc := range s.clients {
		switch tc.kind {
		case kindHEP:
			client := tc.hep
			client.mu.Lock()
			if client.conn != nil {
				_ = client.conn.Close()
				client.conn = nil
			}
			client.state = stateDisconnected
			client.reconnecting = false
			apiserver.SetTransportConnected(client.addr, client.proto, false)
			client.mu.Unlock()
		case kindFlight:
			tc.flight.Close()
		}
	}
	apiserver.SetQueueSize(0)
}

// SendNoErr queues a HEP packet, discarding any error (used by sniffer).
// Satisfies sniffer.Sender and collector.Sender interfaces.
func (s *Sender) SendNoErr(data []byte) {
	_ = s.Send(data)
}
