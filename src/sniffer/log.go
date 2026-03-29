package sniffer

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/decoder"
)

// syslog UDP port
const syslogPort = 514

// startSyslogCapture listens on UDP:514 for syslog messages, extracts Call-ID
// and forwards them as HEP ProtoType=100.
func (s *Sniffer) startSyslogCapture() {
	addr := fmt.Sprintf("0.0.0.0:%d", syslogPort)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("Failed to start syslog listener")
		return
	}
	defer conn.Close()

	log.Info().Str("addr", addr).Msg("Syslog capture listening")

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			log.Debug().Err(err).Msg("Syslog read error")
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		go s.processSyslog(payload, remote)
	}
}

// processSyslog parses a syslog line, extracts Call-ID and sends HEP type=100.
func (s *Sniffer) processSyslog(payload []byte, remote net.Addr) {
	cid := extractSyslogCID(payload)

	udpAddr, _ := net.ResolveUDPAddr("udp", remote.String())
	var srcIP net.IP
	var srcPort uint16
	if udpAddr != nil {
		srcIP = udpAddr.IP
		srcPort = uint16(udpAddr.Port)
	} else {
		srcIP = net.ParseIP("0.0.0.0")
	}

	now := time.Now()
	pkt := &decoder.Packet{
		Version:   0x02,
		Protocol:  0x11,
		SrcIP:     srcIP,
		DstIP:     net.ParseIP("127.0.0.1"),
		SrcPort:   srcPort,
		DstPort:   syslogPort,
		Tsec:      uint32(now.Unix()),
		Tmsec:     uint32(now.Nanosecond() / 1000),
		ProtoType: 100,
		Payload:   payload,
		CID:       cid,
	}

	s.stats.Inc(StatLog)
	s.sendHEP(pkt, 100)
}

// extractSyslogCID tries to extract a SIP Call-ID from a syslog line.
// Supports patterns used by common SIP servers (Kamailio, OpenSIPS, Asterisk, FreeSWITCH).
func extractSyslogCID(line []byte) []byte {
	// Pattern 1: ID=«<callid>»  (UTF-8 «» quotes)
	if idx := bytes.Index(line, []byte("ID=\xc2\xab")); idx >= 0 {
		rest := line[idx+5:]
		if end := bytes.Index(rest, []byte("\xc2\xbb")); end >= 0 {
			return rest[:end]
		}
	}

	// Pattern 2: ID=<callid> (space-terminated)
	if idx := bytes.Index(line, []byte("ID=")); idx >= 0 {
		rest := line[idx+3:]
		if end := bytes.IndexByte(rest, ' '); end >= 0 {
			return rest[:end]
		}
		return rest
	}

	// Pattern 3: INFO: [<callid>]: or INFO: [<callid> port
	for _, prefix := range [][]byte{[]byte("INFO: ["), []byte(": [")} {
		if idx := bytes.Index(line, prefix); idx >= 0 {
			rest := line[idx+len(prefix):]
			if end := bytes.IndexAny(rest, "]: "); end >= 0 {
				return rest[:end]
			}
		}
	}

	return nil
}
