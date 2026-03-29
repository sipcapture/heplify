package collector

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/hep"
	heplifyDecoder "github.com/sipcapture/heplify/src/hep"
)

type Server struct {
	cfg      *config.Config
	sender   Sender
	udpConn  net.PacketConn
	tcpLn    net.Listener
	wg       sync.WaitGroup
	shutdown chan struct{}
}

// Sender is the minimal interface for forwarding re-encoded HEP packets.
type Sender interface {
	SendNoErr(data []byte)
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:      cfg,
		shutdown: make(chan struct{}),
	}
}

// SetSender wires the sender so received HEP is forwarded upstream.
func (s *Server) SetSender(sender Sender) {
	s.sender = sender
}

func (s *Server) Start() error {
	// Find collector configuration from socket settings
	var host string
	var port int
	var proto string

	for _, socket := range s.cfg.SocketSettings {
		if socket.Active && socket.CollectorPort > 0 {
			host = socket.CollectorHost
			if host == "" {
				host = "0.0.0.0"
			}
			port = socket.CollectorPort
			proto = socket.CollectorProto
			if proto == "" {
				proto = "udp"
			}
			break
		}
	}

	if port == 0 {
		// No collector configured
		return nil
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Info().Str("addr", addr).Str("protocol", proto).Msg("Starting Collector Server")

	switch proto {
	case "udp":
		go s.startUDP(addr)
	case "tcp":
		go s.startTCP(addr)
	case "both":
		go s.startUDP(addr)
		go s.startTCP(addr)
	}

	return nil
}

func (s *Server) startUDP(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start UDP listener")
	}
	s.udpConn = pc
	defer pc.Close()

	log.Info().Str("addr", addr).Msg("UDP collector listening")

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				log.Debug().Err(err).Msg("UDP read error")
				continue
			}
		}

		// Make a copy of the data
		data := make([]byte, n)
		copy(data, buf[:n])

		go s.processHEP(data, remoteAddr.String())
	}
}

func (s *Server) startTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start TCP listener")
	}
	s.tcpLn = ln
	defer ln.Close()

	log.Info().Str("addr", addr).Msg("TCP collector listening")

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				log.Error().Err(err).Msg("TCP accept error")
				continue
			}
		}

		s.wg.Add(1)
		go s.handleTCPConnection(conn)
	}
}

func (s *Server) handleTCPConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Debug().Str("addr", remoteAddr).Msg("New TCP connection")

	reader := bufio.NewReaderSize(conn, 65535)

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		// Read HEP packet
		data, err := s.readHEPPacket(reader)
		if err != nil {
			if err == io.EOF {
				log.Debug().Str("addr", remoteAddr).Msg("TCP connection closed")
				return
			}
			log.Debug().Err(err).Str("addr", remoteAddr).Msg("Error reading HEP packet")
			return
		}

		if len(data) > 0 {
			go s.processHEP(data, remoteAddr)
		}
	}
}

// readHEPPacket reads a single HEP packet from the TCP stream
// HEP3 format: "HEP3" + 2-byte length + chunks
func (s *Server) readHEPPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 4)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, err
	}

	if string(header) != "HEP3" {
		return nil, fmt.Errorf("invalid HEP header: %v", header)
	}

	lenBuf := make([]byte, 2)
	_, err = io.ReadFull(reader, lenBuf)
	if err != nil {
		return nil, err
	}

	totalLen := binary.BigEndian.Uint16(lenBuf)
	if totalLen < 6 {
		return nil, fmt.Errorf("invalid HEP packet length: %d", totalLen)
	}

	data := make([]byte, totalLen)
	copy(data[0:4], header)
	copy(data[4:6], lenBuf)

	_, err = io.ReadFull(reader, data[6:])
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *Server) processHEP(data []byte, remoteAddr string) {
	// Decode HEP
	hepMsg, err := heplifyDecoder.DecodeHEP(data)
	if err != nil {
		log.Debug().Err(err).Str("addr", remoteAddr).Msg("Failed to decode HEP")
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

// reEncodeWithNewToken re-builds the HEP packet replacing NodePW (and optionally NodeID/NodeName).
func reEncodeWithNewToken(h *heplifyDecoder.HEP, newPW string, nodeID uint32, nodeName string) []byte {
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
	}
	return hep.Encode(msg)
}

// Stop gracefully stops the collector
func (s *Server) Stop() {
	close(s.shutdown)

	if s.udpConn != nil {
		s.udpConn.Close()
	}

	if s.tcpLn != nil {
		s.tcpLn.Close()
	}

	s.wg.Wait()
	log.Info().Msg("Collector stopped")
}
