package collector

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/apiserver"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/hep"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck // SA1019: h2c still required for cleartext HTTP/2 collector
)

const (
	defaultMaxConnections = 1024
	defaultWorkers        = 8
	defaultReadTimeout    = 60 * time.Second
	// queueSize bounds received-but-not-yet-decoded packets. Beyond it packets
	// are dropped instead of spawning unbounded goroutines.
	queueSize = 10000
)

type job struct {
	data       []byte
	remoteAddr string
}

type Server struct {
	cfg    *config.Config
	sender Sender

	allow       *allowList
	readTimeout time.Duration
	connSlots   chan struct{}
	jobs        chan job

	mu      sync.Mutex // guards the fields below
	udpConn net.PacketConn
	tcpLn   net.Listener
	httpSrv *http.Server
	conns   map[net.Conn]struct{}

	wg        sync.WaitGroup // listeners and connections
	workersWG sync.WaitGroup
	shutdown  chan struct{}
	stopOnce  sync.Once
}

// Sender is the minimal interface for forwarding re-encoded HEP packets.
type Sender interface {
	SendNoErr(data []byte)
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:      cfg,
		shutdown: make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
}

// SetSender wires the sender so received HEP is forwarded upstream.
func (s *Server) SetSender(sender Sender) {
	s.sender = sender
}

func (s *Server) Start() error {
	cs := s.cfg.CollectorSettings
	if !cs.Active || cs.Port == 0 {
		return nil
	}

	allow, err := newAllowList(cs.AllowedCIDRs)
	if err != nil {
		return err
	}
	s.allow = allow

	maxConns := cs.MaxConnections
	if maxConns <= 0 {
		maxConns = defaultMaxConnections
	}
	s.connSlots = make(chan struct{}, maxConns)

	s.readTimeout = defaultReadTimeout
	if cs.ReadTimeoutSec > 0 {
		s.readTimeout = time.Duration(cs.ReadTimeoutSec) * time.Second
	}

	workers := cs.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	s.jobs = make(chan job, queueSize)
	for i := 0; i < workers; i++ {
		s.workersWG.Add(1)
		go s.worker()
	}

	host := cs.Host
	if host == "" {
		host = "0.0.0.0"
	}
	proto := strings.ToLower(cs.Proto)
	if proto == "" {
		proto = "udp"
	}

	addr := net.JoinHostPort(host, fmt.Sprint(cs.Port))
	log.Info().Str("addr", addr).Str("protocol", proto).Msg("Starting Collector Server")
	if allow == nil && cs.AuthToken == "" {
		log.Warn().Str("addr", addr).
			Msg("Collector accepts HEP from any source without authentication; set collector_settings.allowed_cidrs and/or auth_token")
	}
	if s.cfg.HepSettings.ReplaceToken && cs.AuthToken == "" {
		log.Warn().Msg("hep_settings.replace_token re-signs every received packet with node_pw; without collector_settings.auth_token any sender gets a valid token")
	}

	switch proto {
	case "udp":
		s.goListen(func() { s.startUDP(addr) })
	case "tcp":
		s.goListen(func() { s.startTCP(addr, nil) })
	case "both":
		s.goListen(func() { s.startUDP(addr) })
		s.goListen(func() { s.startTCP(addr, nil) })
	case "tls":
		cert, err := tls.LoadX509KeyPair(cs.CertFile, cs.KeyFile)
		if err != nil {
			return fmt.Errorf("collector tls: %w", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		s.goListen(func() { s.startTCP(addr, tlsCfg) })
	case "http2":
		s.goListen(func() { s.startHTTP2(addr) })
	default:
		log.Warn().Str("proto", proto).Msg("Unknown collector protocol, defaulting to udp")
		s.goListen(func() { s.startUDP(addr) })
	}

	return nil
}

func (s *Server) goListen(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
}

func (s *Server) stopping() bool {
	select {
	case <-s.shutdown:
		return true
	default:
		return false
	}
}

// enqueue hands a received packet to the worker pool, dropping it when full.
func (s *Server) enqueue(data []byte, remoteAddr string) {
	select {
	case s.jobs <- job{data: data, remoteAddr: remoteAddr}:
	default:
		apiserver.HepDroppedCount.Inc()
		log.Debug().Str("addr", remoteAddr).Msg("Collector queue full, dropping HEP packet")
	}
}

func (s *Server) worker() {
	defer s.workersWG.Done()
	for {
		select {
		case <-s.shutdown:
			return
		case j := <-s.jobs:
			s.processHEP(j.data, j.remoteAddr)
		}
	}
}

func (s *Server) startUDP(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("Failed to start UDP collector listener")
		return
	}
	s.mu.Lock()
	s.udpConn = pc
	s.mu.Unlock()
	defer pc.Close()

	log.Info().Str("addr", addr).Msg("UDP collector listening")

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debug().Err(err).Msg("UDP read error")
			continue
		}
		if !s.allow.allowedAddr(remoteAddr) {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		s.enqueue(data, remoteAddr.String())
	}
}

func (s *Server) startTCP(addr string, tlsCfg *tls.Config) {
	var ln net.Listener
	var err error
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("Failed to start TCP collector listener")
		return
	}
	s.mu.Lock()
	s.tcpLn = ln
	s.mu.Unlock()
	defer ln.Close()

	log.Info().Str("addr", addr).Bool("tls", tlsCfg != nil).Msg("TCP collector listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error().Err(err).Msg("TCP accept error")
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.allow.allowedAddr(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}
		select {
		case s.connSlots <- struct{}{}:
		default:
			log.Warn().Str("addr", conn.RemoteAddr().String()).Msg("Collector connection limit reached, closing connection")
			_ = conn.Close()
			continue
		}
		s.trackConn(conn, true)
		s.wg.Add(1)
		go s.handleTCPConnection(conn)
	}
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) handleTCPConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.connSlots }()
	defer s.trackConn(conn, false)
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Debug().Str("addr", remoteAddr).Msg("New TCP connection")

	reader := bufio.NewReaderSize(conn, 65535)

	for {
		if s.stopping() {
			return
		}
		// An idle or stalled sender must not hold the connection slot forever.
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))

		data, err := readHEPPacket(reader)
		if err != nil {
			if err == io.EOF {
				log.Debug().Str("addr", remoteAddr).Msg("TCP connection closed")
				return
			}
			log.Debug().Err(err).Str("addr", remoteAddr).Msg("Error reading HEP packet")
			return
		}
		s.enqueue(data, remoteAddr)
	}
}

// readHEPPacket reads a single HEP packet from the TCP stream
// HEP3 format: "HEP3" + 2-byte length + chunks
func readHEPPacket(reader *bufio.Reader) ([]byte, error) {
	var head [6]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return nil, err
	}
	if string(head[:4]) != "HEP3" {
		return nil, fmt.Errorf("invalid HEP header: %x", head[:4])
	}

	totalLen := binary.BigEndian.Uint16(head[4:6])
	if totalLen < 6 {
		return nil, fmt.Errorf("invalid HEP packet length: %d", totalLen)
	}

	data := make([]byte, totalLen)
	copy(data, head[:])
	if _, err := io.ReadFull(reader, data[6:]); err != nil {
		return nil, err
	}
	return data, nil
}

// startHTTP2 starts a cleartext HTTP/2 (h2c) server that receives HEP3 packets
// via POST /hep with Content-Type: application/octet-stream.
// Usage: set collector_proto = "http2" in socket config, or use -hin http2:addr:port
func (s *Server) startHTTP2(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hep", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.allow.allowedHostPort(r.RemoteAddr) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		defer r.Body.Close()

		// Read one byte past the limit so an oversized body is rejected
		// instead of being silently truncated into a broken packet.
		data, err := io.ReadAll(io.LimitReader(r.Body, hep.MaxPacketSize+1))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		if len(data) > hep.MaxPacketSize {
			http.Error(w, "HEP packet too large", http.StatusRequestEntityTooLarge)
			return
		}
		if len(data) < 6 || string(data[0:4]) != "HEP3" {
			http.Error(w, "Not HEP3 Data", http.StatusBadRequest)
			return
		}

		s.enqueue(data, r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	h2s := &http2.Server{MaxConcurrentStreams: 250, IdleTimeout: s.readTimeout}
	srv := &http.Server{
		Addr: addr,
		//nolint:staticcheck // SA1019: h2c still required for cleartext HTTP/2 collector
		Handler:           h2c.NewHandler(mux, h2s),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       s.readTimeout,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       s.readTimeout,
		MaxHeaderBytes:    16 << 10,
	}
	s.mu.Lock()
	s.httpSrv = srv
	s.mu.Unlock()

	log.Info().Str("addr", addr).Msg("HTTP/2 (h2c) collector listening")

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Str("addr", addr).Msg("HTTP/2 collector failed")
	}
}

func (s *Server) processHEP(data []byte, remoteAddr string) {
	defer func() {
		if r := recover(); r != nil {
			apiserver.IncPacketPanic("collector")
			log.Error().
				Interface("panic", r).
				Str("addr", remoteAddr).
				Str("stack", string(debug.Stack())).
				Msg("Recovered from panic while processing HEP")
		}
	}()
	hepMsg, err := hep.DecodeHEP(data)
	if err != nil {
		log.Debug().Err(err).Str("addr", remoteAddr).Msg("Failed to decode HEP")
		return
	}

	if token := s.cfg.CollectorSettings.AuthToken; token != "" && !tokenEqual(hepMsg.NodePW, token) {
		log.Debug().Str("addr", remoteAddr).Msg("Dropping HEP packet with missing or wrong auth token")
		return
	}

	// CollectOnlySIP: drop non-SIP proto types
	if s.cfg.HepSettings.CollectOnlySIP && hepMsg.ProtoType != 1 {
		return
	}

	outData := data
	// ReplaceToken: rebuild packet with our NodePW
	if s.cfg.HepSettings.ReplaceToken && s.cfg.SystemSettings.NodePW != "" {
		outData = reEncodeWithNewToken(hepMsg, s.cfg.SystemSettings.NodePW,
			s.cfg.SystemSettings.NodeID, s.cfg.SystemSettings.NodeName)
		if outData == nil {
			return
		}
	}

	log.Debug().
		Uint32("nodeID", hepMsg.NodeID).
		Str("srcIP", hepMsg.SrcIP).
		Str("dstIP", hepMsg.DstIP).
		Uint32("protoType", hepMsg.ProtoType).
		Str("addr", remoteAddr).
		Msg("Received HEP message")

	if s.sender != nil {
		s.sender.SendNoErr(outData)
	}
}

// tokenEqual compares in constant time, independent of where the strings differ.
func tokenEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// reEncodeWithNewToken re-builds the HEP packet replacing NodePW (and optionally NodeID/NodeName).
func reEncodeWithNewToken(h *hep.HEP, newPW string, nodeID uint32, nodeName string) []byte {
	if nodeID == 0 {
		nodeID = h.NodeID
	}
	if nodeName == "" {
		nodeName = h.NodeName
	}

	var srcIP, dstIP net.IP
	if h.Version == 2 {
		srcIP = net.ParseIP(h.SrcIP).To4()
		dstIP = net.ParseIP(h.DstIP).To4()
	} else {
		srcIP = net.ParseIP(h.SrcIP).To16()
		dstIP = net.ParseIP(h.DstIP).To16()
	}

	msg := &hep.Msg{
		Version:   byte(h.Version),
		Protocol:  byte(h.Protocol),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   uint16(h.SrcPort),
		DstPort:   uint16(h.DstPort),
		Tsec:      h.Tsec,
		Tmsec:     h.Tmsec,
		ProtoType: byte(h.ProtoType),
		NodeID:    nodeID,
		NodePW:    newPW,
		Payload:   []byte(h.Payload),
		CID:       []byte(h.CID),
		Vlan:      uint16(h.Vlan),
		NodeName:  nodeName,
		TCPFlag:   h.TCPFlag,
		IPTos:     h.IPTos,
		MOS:       h.MOS,
	}
	return hep.Encode(msg)
}

// Stop gracefully stops the collector: listeners and open connections are
// closed, so blocked reads return and Stop does not hang.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.shutdown)

		s.mu.Lock()
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
		}
		srv := s.httpSrv
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()

		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
		}

		s.wg.Wait()
		s.workersWG.Wait()
		log.Info().Msg("Collector stopped")
	})
}
