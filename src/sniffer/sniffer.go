package sniffer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	lru "github.com/hashicorp/golang-lru"
	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/decoder"
	"github.com/sipcapture/heplify/src/hep"
	"github.com/sipcapture/heplify/src/script"
	"github.com/sipcapture/heplify/src/transport"
)

// Sender is the minimal interface the sniffer needs to forward HEP packets.
type Sender interface {
	SendNoErr(data []byte)
	SendRecord(r transport.PacketRecord)
	HasFlightClients() bool
}

// PacketSource interface for different capture methods
type PacketSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Close()
	LinkType() layers.LinkType
}

// pcapWrapper wraps pcap.Handle to implement PacketSource
type pcapWrapper struct {
	handle *pcap.Handle
}

func (p *pcapWrapper) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return p.handle.ReadPacketData()
}

func (p *pcapWrapper) Close() {
	p.handle.Close()
}

func (p *pcapWrapper) LinkType() layers.LinkType {
	return p.handle.LinkType()
}

// Sniffer manages packet capture and processing
type Sniffer struct {
	cfg        *config.Config
	lua        *script.Engine
	sender     Sender
	dedupCache *lru.Cache
	stats      *Stats
	debug      debugFlags
}

type debugFlags struct {
	defrag     bool
	layer      bool
	payload    bool
	rtp        bool
	rtcp       bool
	sdp        bool
	logPayload bool // print SIP payload as plain text
}

var (
	processedPacketsForDebug uint64
	queuedForHepDebug        uint64
	matchedForDebug          uint64
	sipProcessingDebug       uint64
	unmatchedForDebug        uint64
)

func parseDebugFlags(selectors []string) debugFlags {
	f := debugFlags{}
	for _, s := range selectors {
		switch s {
		case "defrag":
			f.defrag = true
		case "layer":
			f.layer = true
		case "payload":
			f.payload = true
		case "rtp":
			f.rtp = true
		case "rtcp":
			f.rtcp = true
		case "sdp":
			f.sdp = true
		}
	}
	return f
}

// New creates a new Sniffer. sender may be nil during testing.
func New(cfg *config.Config, lua *script.Engine) *Sniffer {
	cache, _ := lru.New(10000)
	dbg := parseDebugFlags(cfg.DebugSelectors)
	dbg.logPayload = cfg.LogSettings.LogPayload
	return &Sniffer{
		cfg:        cfg,
		lua:        lua,
		dedupCache: cache,
		stats:      NewStats(),
		debug:      dbg,
	}
}

// SetSender wires the sender so captured packets are forwarded as HEP.
func (s *Sniffer) SetSender(sender Sender) {
	s.sender = sender
}

// GetStats returns the Stats instance for external access (e.g. web stats endpoint).
func (s *Sniffer) GetStats() *Stats {
	return s.stats
}

// Start begins packet capture for all active socket settings.
func (s *Sniffer) Start() error {
	for _, socket := range s.cfg.SocketSettings {
		if !socket.Active {
			continue
		}

		// Start LOG/Syslog listener if SIPLOG mode is active
		if hasCaptureMode(socket.CaptureMode, "LOG") {
			go s.startSyslogCapture()
		}

		if socket.SocketType == "afpacket" && socket.FanoutWorkers > 1 {
			for i := 0; i < socket.FanoutWorkers; i++ {
				go s.captureAFPacket(socket, i)
			}
		} else {
			go s.capture(socket)
		}
	}
	// Start per-minute stats logging
	go s.stats.RunLogger()
	return nil
}

func (s *Sniffer) capture(socket config.SocketSettings) {
	log.Info().Str("interface", socket.Device).Str("type", socket.SocketType).Msg("Starting capture")

	snapLen := socket.SnapLen
	if snapLen == 0 {
		snapLen = 65535
	}

	var source PacketSource
	var err error

	switch socket.SocketType {
	case "afpacket":
		source, err = s.createAFPacketSource(socket, snapLen, 0)
	default:
		source, err = s.createPcapSource(socket, snapLen)
	}
	if err != nil {
		log.Error().Err(err).Msg("Failed to create packet source")
		return
	}
	defer source.Close()

	var dumpCh chan<- dumpPacket
	if s.cfg.PcapSettings.WriteFile != "" {
		ch := make(chan dumpPacket, 100000)
		go s.dumpPcap(ch, socket.Device, source.LinkType())
		dumpCh = ch
	}

	s.processPackets(source, socket, dumpCh)
}

func (s *Sniffer) captureAFPacket(socket config.SocketSettings, workerID int) {
	snapLen := socket.SnapLen
	if snapLen == 0 {
		snapLen = 65535
	}
	source, err := s.createAFPacketSource(socket, snapLen, workerID)
	if err != nil {
		log.Error().Err(err).Int("worker", workerID).Msg("Failed to create AF_PACKET source")
		return
	}
	defer source.Close()

	var dumpCh chan<- dumpPacket
	if s.cfg.PcapSettings.WriteFile != "" {
		ch := make(chan dumpPacket, 100000)
		go s.dumpPcap(ch, fmt.Sprintf("%s_w%d", socket.Device, workerID), source.LinkType())
		dumpCh = ch
	}

	s.processPackets(source, socket, dumpCh)
}

func (s *Sniffer) createPcapSource(socket config.SocketSettings, snapLen int) (PacketSource, error) {
	var handle *pcap.Handle
	var err error

	if socket.PcapFile != "" {
		handle, err = pcap.OpenOffline(socket.PcapFile)
	} else {
		handle, err = pcap.OpenLive(socket.Device, int32(snapLen), socket.Promisc, 1*time.Second)
	}
	if err != nil {
		return nil, err
	}

	filter := socket.BPFFilter
	if filter == "" && socket.PcapFile == "" && len(socket.CaptureMode) > 0 {
		filter = s.buildBPFFilter(socket)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Error().Err(err).Str("filter", filter).Msg("Failed to set BPF filter")
		}
	}
	return &pcapWrapper{handle: handle}, nil
}

func (s *Sniffer) createAFPacketSource(socket config.SocketSettings, snapLen int, _ int) (PacketSource, error) {
	if !afpacketSupported() {
		return nil, fmt.Errorf("AF_PACKET is not supported on this platform")
	}

	bufferMB := socket.BufferSizeMB
	if bufferMB == 0 {
		bufferMB = 32
	}

	pageSize := os.Getpagesize()
	frameSize, blockSize, numBlocks, err := afpacketComputeSize(bufferMB, snapLen, pageSize)
	if err != nil {
		return nil, err
	}

	handle, err := newAfpacketHandle(socket.Device, frameSize, blockSize, numBlocks,
		1*time.Second, socket.Vlan)
	if err != nil {
		return nil, err
	}

	if socket.FanoutID > 0 {
		if err := handle.SetFanout(socket.FanoutID); err != nil {
			log.Warn().Err(err).Msg("Failed to set fanout, continuing without")
		}
	}

	filter := socket.BPFFilter
	if filter == "" && len(socket.CaptureMode) > 0 {
		filter = s.buildBPFFilter(socket)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter, snapLen); err != nil {
			log.Error().Err(err).Str("filter", filter).Msg("Failed to set BPF filter")
		}
	}
	return handle, nil
}

func (s *Sniffer) buildBPFFilter(socket config.SocketSettings) string {
	var parts []string

	for _, proto := range s.cfg.ProtocolSettings {
		if proto.MinPort == 0 && proto.MaxPort == 0 {
			continue
		}
		portExpr := ""
		if proto.MinPort == proto.MaxPort {
			portExpr = fmt.Sprintf("port %d", proto.MinPort)
		} else {
			portExpr = fmt.Sprintf("portrange %d-%d", proto.MinPort, proto.MaxPort)
		}
		for _, p := range proto.Protocol {
			switch p {
			case "udp":
				parts = append(parts, fmt.Sprintf("(udp and %s)", portExpr))
			case "tcp":
				parts = append(parts, fmt.Sprintf("(tcp and %s)", portExpr))
			}
		}
	}

	var filter string
	if len(parts) > 0 {
		filter = strings.Join(parts, " or ")
	} else {
		filter = "udp or tcp"
	}

	if socket.Erspan {
		filter = fmt.Sprintf("(%s) or proto 47", filter)
	}
	if hasCaptureMode(socket.CaptureMode, "DNS") {
		filter = fmt.Sprintf("(%s) or (udp port 53)", filter)
	}
	if socket.Vlan {
		filter = fmt.Sprintf("(%s) or (vlan and (%s))", filter, filter)
	}

	log.Info().Str("filter", filter).Str("interface", socket.Device).Msg("BPF filter applied")
	return filter
}

func (s *Sniffer) processPackets(source PacketSource, socket config.SocketSettings, dumpCh chan<- dumpPacket) {
	dec := decoder.NewDecoder(source.LinkType())
	packetCount := 0

	// IP defragmentation: enabled by default, disabled via disable_ip_defrag.
	if s.cfg.DebugSettings.DisableIPDefrag {
		dec.DisableDefrag()
	}

	// TCP reassembly: enabled by default, disabled via disable_tcp_reassembly.
	if !s.cfg.DebugSettings.DisableTcpReassembly {
		dec.TCPAssembler = decoder.NewSIPAssembler(func(pkt *decoder.Packet) {
			s.handleSIP(pkt)
		})
		// Flush streams that have been silent for >30 s, checked every second.
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				dec.TCPAssembler.FlushOlderThan(time.Now().Add(-30 * time.Second))
			}
		}()
	}

	loopCount := s.cfg.PcapSettings.LoopCount
	loopsDone := 0
	pcapFile := socket.PcapFile

	for {
		data, ci, err := source.ReadPacketData()
		if err != nil {
			if afh, ok := source.(*afpacketHandle); ok && afh.IsErrTimeout(err) {
				continue
			}
			if err.Error() == "EOF" {
				if pcapFile != "" {
					// pcap replay finished
					loopsDone++
					if s.cfg.PcapSettings.EOFExit || (loopCount > 0 && loopsDone >= loopCount) {
						log.Info().Msg("End of pcap file, exiting")
						os.Exit(0)
					}
					// Loop: reopen the file
					newHandle, rerr := pcap.OpenOffline(pcapFile)
					if rerr != nil {
						log.Error().Err(rerr).Msg("Failed to reopen pcap file for loop")
						return
					}
					source.Close()
					source = &pcapWrapper{handle: newHandle}
					dec = decoder.NewDecoder(source.LinkType())
					log.Info().Int("loop", loopsDone+1).Msg("Restarting pcap replay")
					continue
				}
				log.Info().Msg("End of pcap file")
				return
			}
			log.Debug().Err(err).Msg("Error reading packet")
			continue
		}
		packetCount++
		if packetCount <= 5 || packetCount%100 == 0 {
			log.Debug().
				Str("interface", socket.Device).
				Str("capture_type", socket.SocketType).
				Int("length", len(data)).
				Int("caplen", ci.Length).
				Int("num", packetCount).
				Msg("Received packet from interface")
		}

		// MaxSpeed: ignore packet timestamps when replaying pcap
		if pcapFile != "" && s.cfg.PcapSettings.MaxSpeed {
			ci.Timestamp = time.Now()
		}

		if dumpCh != nil {
			select {
			case dumpCh <- dumpPacket{ci, data}:
			default:
			}
		}

		s.stats.Inc(StatTotal)
		s.processPacket(data, ci, dec, socket)
	}
}

func (s *Sniffer) processPacket(data []byte, ci gopacket.CaptureInfo, dec *decoder.Decoder, socket config.SocketSettings) {
	processedNum := atomic.AddUint64(&processedPacketsForDebug, 1)
	pkt, err := dec.Decode(data, ci)
	if err != nil || pkt == nil {
		return
	}

	if processedNum <= 5 || processedNum%100 == 0 {
		log.Debug().
			Str("interface", socket.Device).
			Str("capture_type", socket.SocketType).
			Str("timestamp", ci.Timestamp.Format(time.RFC3339Nano)).
			Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
			Int("len", len(data)).
			Int("payload", len(pkt.Payload)).
			Str("payload_hex", formatPayloadHex(pkt.Payload)).
			Uint64("num", processedNum).
			Msg("Start processing packet")
	}

	if s.debug.layer {
		log.Debug().
			Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Str("dst", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
			Uint8("proto", pkt.Protocol).
			Msg("[layer] decoded packet")
	}

	if len(pkt.Payload) == 0 {
		return
	}

	// Global include-filter: payload must contain ALL strings
	for _, include := range s.cfg.FilterInclude {
		if !bytes.Contains(pkt.Payload, []byte(include)) {
			return
		}
	}
	// Global exclude-filter: drop if payload contains ANY string
	for _, exclude := range s.cfg.FilterExclude {
		if bytes.Contains(pkt.Payload, []byte(exclude)) {
			return
		}
	}

	// IP filtering
	srcIPStr := pkt.SrcIP.String()
	dstIPStr := pkt.DstIP.String()
	for _, ip := range s.cfg.SipSettings.DiscardIPs {
		if srcIPStr == ip || dstIPStr == ip {
			return
		}
	}
	for _, ip := range s.cfg.SipSettings.DiscardSrcIP {
		if srcIPStr == ip {
			return
		}
	}
	for _, ip := range s.cfg.SipSettings.DiscardDstIP {
		if dstIPStr == ip {
			return
		}
	}

	// Deduplication (global, keyed on full payload)
	if s.cfg.HepSettings.Deduplicate && s.dedupCache != nil {
		key := string(pkt.Payload)
		if s.dedupCache.Contains(key) {
			s.stats.Inc(StatDuplicates)
			return
		}
		s.dedupCache.Add(key, struct{}{})
	}

	// Match against configured protocols
	for _, protoSetting := range s.cfg.ProtocolSettings {
		if !matchProtocol(protoSetting, pkt.Protocol) {
			continue
		}
		if !(matchPort(protoSetting, pkt.SrcPort) || matchPort(protoSetting, pkt.DstPort)) {
			continue
		}
		dispatchNum := atomic.AddUint64(&matchedForDebug, 1)
		if dispatchNum <= 5 || dispatchNum%100 == 0 {
			log.Debug().
				Uint64("num", dispatchNum).
				Str("protocol", protoSetting.Name).
				Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
				Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
				Uint16("src_port", pkt.SrcPort).
				Uint16("dst_port", pkt.DstPort).
				Uint8("proto", pkt.Protocol).
				Msg("Packet matched configured protocol")
		}

		s.handleProtocol(pkt, protoSetting, socket)
		return
	}

	// DNS handling (port 53, any protocol)
	if hasCaptureMode(socket.CaptureMode, "DNS") {
		if pkt.SrcPort == 53 || pkt.DstPort == 53 {
			s.handleDNS(pkt)
			return
		}
	}

	// If debug is enabled and a non-matching UDP/TCP packet was processed,
	// emit a short trace to make it obvious why SIP wasn't handled.
	if pkt.Protocol == 0x11 || pkt.Protocol == 0x06 {
		s.stats.Inc(StatUnknown)
		unmatchedNum := atomic.AddUint64(&unmatchedForDebug, 1)
		if unmatchedNum <= 5 || unmatchedNum%100 == 0 {
			log.Debug().
				Uint64("num", unmatchedNum).
				Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
				Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
				Uint16("src_port", pkt.SrcPort).
				Uint16("dst_port", pkt.DstPort).
				Uint8("proto", pkt.Protocol).
				Str("reason", "no configured protocol/port match").
				Int("payload", len(pkt.Payload)).
				Str("payload_hex", formatPayloadHex(pkt.Payload)).
				Msg("Packet ignored by protocol filter")
		}
	}
}

func (s *Sniffer) handleProtocol(pkt *decoder.Packet, proto config.ProtocolSettings, _ config.SocketSettings) {
	switch proto.Name {
	case "SIP":
		s.handleSIP(pkt)
	case "RTCP":
		s.handleRTCP(pkt)
	case "RTP":
		s.handleRTP(pkt)
	case "DNS":
		s.handleDNS(pkt)
	case "HEP":
		// Incoming HEP in sniffer mode — forward as-is
		if s.sender != nil {
			s.sender.SendNoErr(pkt.Payload)
		}
	default:
		s.sendHEP(pkt, 99)
	}
}

func (s *Sniffer) handleSIP(pkt *decoder.Packet) {
	sipNum := atomic.AddUint64(&sipProcessingDebug, 1)

	if s.debug.logPayload && len(pkt.Payload) > 0 {
		log.Debug().
			Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
			Str("payload", string(pkt.Payload)).
			Msg("SIP packet")
	} else if sipNum <= 20 || sipNum%50 == 0 {
		log.Debug().
			Uint64("num", sipNum).
			Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
			Uint8("proto", pkt.Protocol).
			Str("proto_type", "1").
			Int("payload", len(pkt.Payload)).
			Str("payload_hex", formatPayloadHex(pkt.Payload)).
			Msg("Handling SIP packet")
	}

	if len(pkt.Payload) == 0 {
		return
	}

	// WebSocket handling for TCP packets
	if pkt.Protocol == 0x06 {
		if decoder.IsWebSocketUpgrade(pkt.Payload) {
			// WS handshake — skip, but note the stream
			if s.debug.layer {
				log.Debug().Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).Msg("[ws] WebSocket upgrade")
			}
			return
		}
		if decoder.IsWebSocketFrame(pkt.Payload) {
			sipPayload, err := decoder.ExtractSIPFromWebSocket(pkt.Payload)
			if err != nil || len(sipPayload) == 0 {
				return
			}
			if s.debug.layer {
				log.Debug().Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).Msg("[ws] SIP-over-WebSocket")
			}
			pkt.Payload = sipPayload
		}
	}

	// SIP method discard
	for _, method := range s.cfg.SipSettings.DiscardMethods {
		if len(pkt.Payload) >= len(method) && string(pkt.Payload[:len(method)]) == method {
			return
		}
	}

	// Extract Call-ID for RTCP correlation
	decoder.ExtractCID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)

	if s.debug.sdp {
		log.Debug().Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).Msg("[sdp] SIP packet")
	}

	pkt.ProtoType = 1
	s.callLua(pkt)
	s.stats.Inc(StatSIP)
	s.sendHEP(pkt, 1)
}

func (s *Sniffer) handleRTCP(pkt *decoder.Packet) {
	if !s.cfg.RtcpSettings.Active {
		return
	}
	jsonData, cid, mos := decoder.CorrelateRTCP(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Payload)
	if jsonData == nil {
		s.stats.Inc(StatRTCPFail)
		return
	}

	if s.debug.rtcp {
		log.Debug().
			Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Uint16("mos100", mos).
			Msg("[rtcp] correlated")
	}

	pkt.ProtoType = 5
	pkt.Payload = jsonData
	pkt.CID = cid
	s.stats.Inc(StatRTCP)
	s.sendHEPWithMOS(pkt, 5, mos)
}

func (s *Sniffer) handleRTP(pkt *decoder.Packet) {
	// RFC 5761 rtcp-mux: RTCP multiplexed on the RTP port.
	// Detect by RTP version==2 and RTCP payload type range [200,223].
	if len(pkt.Payload) >= 2 &&
		(pkt.Payload[0]&0xC0)>>6 == 2 &&
		pkt.Payload[1] >= 200 && pkt.Payload[1] <= 223 {
		s.handleRTCP(pkt)
		return
	}
	if s.debug.rtp {
		log.Debug().Str("src", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).Msg("[rtp] packet")
	}
	s.stats.Inc(StatRTP)
}

func (s *Sniffer) handleDNS(pkt *decoder.Packet) {
	jsonData := decoder.ParseDNS(pkt.Payload)
	if jsonData == nil {
		return
	}
	pkt.ProtoType = 53
	pkt.Payload = jsonData
	s.stats.Inc(StatDNS)
	s.sendHEP(pkt, 53)
}

func (s *Sniffer) callLua(pkt *decoder.Packet) {
	if s.lua == nil {
		return
	}
	s.lua.SetPacket(pkt)
	s.lua.OnPacket(fmt.Sprintf("%d", pkt.ProtoType))
}

func (s *Sniffer) sendHEP(pkt *decoder.Packet, protoType byte) {
	s.sendHEPWithMOS(pkt, protoType, 0)
}

func (s *Sniffer) sendHEPWithMOS(pkt *decoder.Packet, protoType byte, mos uint16) {
	if s.sender == nil {
		return
	}

	sendNum := atomic.AddUint64(&queuedForHepDebug, 1)
	if sendNum <= 5 || sendNum%100 == 0 {
		log.Debug().
			Uint64("num", sendNum).
			Str("source", fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)).
			Str("destination", fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)).
			Uint16("proto", uint16(pkt.Protocol)).
			Uint8("proto_type", protoType).
			Int("payload", len(pkt.Payload)).
			Str("payload_hex", formatPayloadHex(pkt.Payload)).
			Msg("Queue packet for HEP sending")
	}

	// Arrow Flight path: send structured record, skip HEP encoding entirely.
	if s.sender.HasFlightClients() {
		ts := uint64(pkt.Tsec)*1_000_000 + uint64(pkt.Tmsec)
		s.sender.SendRecord(transport.PacketRecord{
			TimestampUs: ts,
			SrcIP:       pkt.SrcIP,
			DstIP:       pkt.DstIP,
			SrcPort:     pkt.SrcPort,
			DstPort:     pkt.DstPort,
			IPProtocol:  pkt.Protocol,
			ProtoType:   protoType,
			Payload:     pkt.Payload,
			CID:         pkt.CID,
			NodeID:      s.cfg.SystemSettings.NodeID,
			NodeName:    s.cfg.SystemSettings.NodeName,
			MOS:         mos,
		})
		s.stats.Inc(StatHEPSent)
		return
	}

	// HEP path (UDP / TCP / TLS)
	msg := &hep.Msg{
		Version:   pkt.Version,
		Protocol:  pkt.Protocol,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Tsec:      pkt.Tsec,
		Tmsec:     pkt.Tmsec,
		ProtoType: protoType,
		NodeID:    s.cfg.SystemSettings.NodeID,
		NodePW:    s.cfg.SystemSettings.NodePW,
		NodeName:  s.cfg.SystemSettings.NodeName,
		Payload:   pkt.Payload,
		CID:       pkt.CID,
		Vlan:      pkt.Vlan,
		TCPFlag:   pkt.TCPFlag,
		IPTos:     pkt.IPTos,
		MOS:       mos,
	}

	if s.debug.payload {
		log.Debug().Str("payload", string(pkt.Payload[:min(200, len(pkt.Payload))])).Msg("[payload]")
	}

	s.sender.SendNoErr(hep.Encode(msg))
	s.stats.Inc(StatHEPSent)
}

// --- helpers ---

func matchProtocol(setting config.ProtocolSettings, proto byte) bool {
	for _, p := range setting.Protocol {
		switch p {
		case "udp":
			if proto == 0x11 {
				return true
			}
		case "tcp":
			if proto == 0x06 {
				return true
			}
		case "sctp":
			if proto == 0x84 {
				return true
			}
		}
	}
	return false
}

func matchPort(setting config.ProtocolSettings, port uint16) bool {
	return port >= setting.MinPort && port <= setting.MaxPort
}

func hasCaptureMode(modes []string, mode string) bool {
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatPayloadHex(payload []byte) string {
	const maxLen = 128
	if len(payload) == 0 {
		return ""
	}
	limit := maxLen
	if len(payload) < limit {
		limit = len(payload)
	}
	return hex.EncodeToString(payload[:limit])
}
