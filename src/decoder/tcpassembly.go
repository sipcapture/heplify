package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// SIPCallback is invoked synchronously when a complete SIP message has been
// reassembled from a TCP stream.
type SIPCallback func(pkt *Packet)

// SIPAssembler wraps gopacket's TCP stream assembler and calls cb whenever a
// complete SIP (or SIP-over-WebSocket) message is reassembled.
type SIPAssembler struct {
	asm *tcpassembly.Assembler
	mu  sync.Mutex
}

// NewSIPAssembler creates a SIPAssembler that calls cb for every reassembled
// SIP message.  Call FlushOlderThan periodically to release stale streams.
func NewSIPAssembler(cb SIPCallback) *SIPAssembler {
	factory := &sipStreamFactory{cb: cb}
	pool := tcpassembly.NewStreamPool(factory)
	return &SIPAssembler{asm: tcpassembly.NewAssembler(pool)}
}

// Feed passes a single TCP segment to the assembler.
func (a *SIPAssembler) Feed(netFlow gopacket.Flow, tcp *layers.TCP, ts time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asm.AssembleWithTimestamp(netFlow, tcp, ts)
}

// FlushOlderThan releases streams that have not received data since t.
func (a *SIPAssembler) FlushOlderThan(t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asm.FlushOlderThan(t)
}

// FlushAll delivers and closes every stream (end of a pcap file).
func (a *SIPAssembler) FlushAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asm.FlushAll()
}

// ── stream factory ────────────────────────────────────────────────────────────

type sipStreamFactory struct{ cb SIPCallback }

func (f *sipStreamFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	return &sipStream{
		net:       netFlow,
		transport: transport,
		cb:        f.cb,
		buf:       make([]byte, 0, 4096),
	}
}

// ── per-connection stream ─────────────────────────────────────────────────────

type sipStream struct {
	net, transport gopacket.Flow
	cb             SIPCallback
	buf            []byte
	ts             time.Time
	// tsSeq assigns distinct HEP Tmsec values when multiple SIP messages share
	// one TCP capture timestamp (same segment). Homer sorts by (Tsec, Tmsec).
	tsSeq uint32
}

func (s *sipStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		if r.Skip != 0 {
			// Gap (or half-open stream — no SYN captured). The accumulated
			// buffer is no longer contiguous so discard it, but do NOT skip
			// r.Bytes. The bytes that follow the gap often start at a SIP
			// message boundary (each SIP request/response is typically the
			// first payload in a TCP segment). Falling through lets us resync
			// immediately instead of waiting for the connection to be torn
			// down and a new SYN to be captured.
			s.buf = s.buf[:0]
			s.clearTimestamp()
			// fall through ↓
		}
		if len(r.Bytes) == 0 {
			continue
		}
		if s.ts.IsZero() {
			s.ts = r.Seen
			s.tsSeq = 0
		}
		s.buf = append(s.buf, r.Bytes...)
		// A single Reassembled callback can contain data from multiple TCP
		// segments, each with its own capture timestamp. Process after each
		// entry so a complete SIP message does not inherit the timestamp of
		// the first segment in the whole callback batch.
		s.process()
	}
}

func (s *sipStream) ReassemblyComplete() {
	s.buf = s.buf[:0]
}

func (s *sipStream) process() {
	for len(s.buf) > 0 {
		// Diameter over TCP: Length-framed binary messages (version byte 0x01).
		// Checked before SIP so Diameter/TCP shares the same assembler safely.
		if len(s.buf) >= DiameterHeaderLen && s.buf[0] == 0x01 {
			msgLen := DiameterMessageLength(s.buf)
			if msgLen == 0 {
				// Not a valid Diameter header — fall through to SIP/other.
			} else if msgLen > maxStreamBuffer {
				// Would never fit in the buffer: drop and resync.
				s.resetBuffer()
				return
			} else if msgLen > len(s.buf) {
				return // wait for more data
			} else {
				payload := make([]byte, msgLen)
				copy(payload, s.buf[:msgLen])
				pkt := s.buildPacket(payload)
				if pkt != nil {
					s.cb(pkt)
				}
				s.buf = s.buf[msgLen:]
				if len(s.buf) == 0 {
					s.clearTimestamp()
				}
				continue
			}
		}

		// Skip HTTP upgrade / WebSocket handshake framing.
		if bytes.HasPrefix(s.buf, []byte("GET ")) || bytes.HasPrefix(s.buf, []byte("HTTP/")) {
			end := bytes.Index(s.buf, []byte("\r\n\r\n"))
			if end < 0 {
				if len(s.buf) > maxStreamBuffer {
					s.resetBuffer()
				}
				return // wait for more data
			}
			s.buf = s.buf[end+4:]
			s.clearTimestamp()
			continue
		}

		// SIP-over-WebSocket: try to unwrap the WS frame first.
		if IsWebSocketFrame(s.buf) || isWSControlFrame(s.buf) {
			frameLen, err := WSFrameLen(s.buf)
			if err != nil {
				if errors.Is(err, ErrWSHeaderTooShort) && len(s.buf) <= maxStreamBuffer {
					return // incomplete WS frame, wait for more
				}
				s.resetBuffer()
				return
			}
			if frameLen > maxStreamBuffer {
				s.resetBuffer()
				return
			}
			if frameLen > len(s.buf) {
				return // wait for more data
			}
			if sipPayload, err := ExtractSIPFromWebSocket(s.buf[:frameLen]); err == nil && len(sipPayload) > 0 {
				if pkt := s.buildPacket(sipPayload); pkt != nil {
					s.cb(pkt)
				}
			}
			// Skip exactly one frame (ping/pong/non-SIP frames are dropped too).
			s.buf = s.buf[frameLen:]
			if len(s.buf) == 0 {
				s.clearTimestamp()
			}
			continue
		}

		payload, err := parseSIPMessage(s.buf)
		switch {
		case errors.Is(err, errSIPTruncated):
			if len(s.buf) > maxStreamBuffer {
				s.resetBuffer()
			}
			return // wait for more data
		case err != nil:
			// Too large, not SIP or corrupted: drop once the buffer is big
			// (or right away for an oversized message).
			if errors.Is(err, errSIPTooLarge) || len(s.buf) > maxStreamBuffer {
				s.resetBuffer()
			}
			return
		}

		pkt := s.buildPacket(payload)
		if pkt != nil {
			s.cb(pkt)
		}
		s.buf = s.buf[len(payload):]
		// When the buffer is empty, clear the timestamp so the next
		// Reassembled() call picks up a fresh r.Seen for the next segment.
		// While data remains, consecutive SIP messages keep the same capture
		// second but receive incrementing Tmsec via tsSeq (issue #342).
		if len(s.buf) == 0 {
			s.clearTimestamp()
		}
	}
}

// isWSControlFrame reports a final close/ping/pong frame. Those carry no SIP
// but must be skipped, or the stream stalls behind them.
func isWSControlFrame(b []byte) bool {
	return len(b) >= 2 && (b[0] == 0x88 || b[0] == 0x89 || b[0] == 0x8A)
}

// resetBuffer drops all buffered data for the stream.
func (s *sipStream) resetBuffer() {
	s.buf = s.buf[:0]
	s.clearTimestamp()
}

func (s *sipStream) clearTimestamp() {
	s.ts = time.Time{}
	s.tsSeq = 0
}

// hepTimestampFromCapture maps a capture time and sub-message sequence to HEP fields.
func hepTimestampFromCapture(ts time.Time, seq uint32) (tsec, tmsec uint32) {
	tsec = uint32(ts.Unix())
	us := uint64(ts.Nanosecond()/1000) + uint64(seq)
	if us >= 1_000_000 {
		tsec += uint32(us / 1_000_000)
		tmsec = uint32(us % 1_000_000)
		return tsec, tmsec
	}
	return tsec, uint32(us)
}

func (s *sipStream) buildPacket(payload []byte) *Packet {
	srcRaw := s.net.Src().Raw()
	dstRaw := s.net.Dst().Raw()
	spRaw := s.transport.Src().Raw()
	dpRaw := s.transport.Dst().Raw()

	if len(spRaw) != 2 || len(dpRaw) != 2 {
		return nil
	}

	pkt := &Packet{
		Protocol: 0x06,
		SrcPort:  binary.BigEndian.Uint16(spRaw),
		DstPort:  binary.BigEndian.Uint16(dpRaw),
		Payload:  make([]byte, len(payload)), // must copy — buf is reused
	}
	copy(pkt.Payload, payload)

	switch len(srcRaw) {
	case 4:
		pkt.Version = 0x02
		pkt.SrcIP = make(net.IP, 4)
		copy(pkt.SrcIP, srcRaw)
		pkt.DstIP = make(net.IP, 4)
		copy(pkt.DstIP, dstRaw)
	case 16:
		pkt.Version = 0x0a
		pkt.SrcIP = make(net.IP, 16)
		copy(pkt.SrcIP, srcRaw)
		pkt.DstIP = make(net.IP, 16)
		copy(pkt.DstIP, dstRaw)
	default:
		return nil
	}

	if !s.ts.IsZero() {
		pkt.Tsec, pkt.Tmsec = hepTimestampFromCapture(s.ts, s.tsSeq)
		s.tsSeq++
	}
	return pkt
}

// ── SIP message parser ────────────────────────────────────────────────────────

var (
	errSIPTruncated = errors.New("truncated SIP message")
	errNotSIP       = errors.New("not SIP")
	errSIPTooLarge  = errors.New("SIP message exceeds stream buffer limit")
)

// maxStreamBuffer caps how much unparsed data one TCP stream may hold.
// SIP and Diameter messages larger than this are dropped.
const maxStreamBuffer = 1 << 20

var sipPrefixes = [][]byte{
	[]byte("SIP/2.0 "),
	[]byte("INVITE "), []byte("ACK "), []byte("BYE "), []byte("CANCEL "),
	[]byte("REGISTER "), []byte("OPTIONS "), []byte("SUBSCRIBE "),
	[]byte("NOTIFY "), []byte("REFER "), []byte("INFO "), []byte("UPDATE "),
	[]byte("PRACK "), []byte("PUBLISH "), []byte("MESSAGE "),
}

// parseSIPMessage returns a single complete SIP message from data, or an error.
// errSIPTruncated means the message starts correctly but is not yet complete.
func parseSIPMessage(data []byte) ([]byte, error) {
	ok := false
	for _, p := range sipPrefixes {
		if bytes.HasPrefix(data, p) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errNotSIP
	}

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, errSIPTruncated
	}
	headerEnd += 4

	bodyLen := sipContentLength(data)
	if bodyLen < 0 {
		bodyLen = 0
	}
	if bodyLen > maxStreamBuffer-headerEnd {
		return nil, errSIPTooLarge
	}

	total := headerEnd + bodyLen
	if len(data) < total {
		return nil, errSIPTruncated
	}
	return data[:total], nil
}

// sipContentLength extracts the numeric value of the Content-Length header.
var clNames = [][]byte{
	[]byte("\r\nContent-Length:"),
	[]byte("\r\nContent-length:"),
	[]byte("\r\ncontent-length:"),
	[]byte("\r\nl:"),
}

func sipContentLength(data []byte) int {
	for _, name := range clNames {
		pos := bytes.Index(data, name)
		if pos < 0 {
			continue
		}
		rest := data[pos+len(name):]
		eol := bytes.Index(rest, []byte("\r\n"))
		if eol < 0 {
			continue
		}
		val := bytes.TrimSpace(rest[:eol])
		n, valid := 0, false
		for _, c := range val {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
			if n > maxStreamBuffer {
				// Absurd length: report it as too big instead of overflowing int.
				return maxStreamBuffer + 1
			}
			valid = true
		}
		if valid {
			return n
		}
	}
	return -1
}
