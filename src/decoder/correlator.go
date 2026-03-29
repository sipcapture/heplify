package decoder

import (
	"bytes"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// CIDCache stores Call-ID correlations for RTCP
type CIDCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

type cacheItem struct {
	value   []byte
	expires time.Time
}

// RTCPCache stores RTCP to Call-ID mappings
type RTCPCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

var (
	// cidCache stores IP:port -> Call-ID mappings from SDP
	cidCache = NewCIDCache()
	// rtcpCache stores IP:port:SSRC -> Call-ID mappings
	rtcpCache = NewRTCPCache()

	// Cache timeouts
	cidCacheTimeout  = 20 * time.Minute
	rtcpCacheTimeout = 12 * time.Hour
)

// NewCIDCache creates a new CID cache
func NewCIDCache() *CIDCache {
	c := &CIDCache{
		items: make(map[string]cacheItem),
	}
	go c.cleanup()
	return c
}

// NewRTCPCache creates a new RTCP cache
func NewRTCPCache() *RTCPCache {
	c := &RTCPCache{
		items: make(map[string]cacheItem),
	}
	go c.cleanup()
	return c
}

func (c *CIDCache) Set(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cacheItem{
		value:   value,
		expires: time.Now().Add(cidCacheTimeout),
	}
}

func (c *CIDCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expires) {
		return nil, false
	}
	return item.value, true
}

func (c *CIDCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expires) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

func (c *RTCPCache) Set(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cacheItem{
		value:   value,
		expires: time.Now().Add(rtcpCacheTimeout),
	}
}

func (c *RTCPCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expires) {
		return nil, false
	}
	return item.value, true
}

func (c *RTCPCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expires) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// Header names for SIP parsing
var (
	contentTypeHeaderNames = [][]byte{
		[]byte("Content-Type:"),
		[]byte("content-type:"),
		[]byte("c:"),
	}
	callIdHeaderNames = [][]byte{
		[]byte("Call-ID:"),
		[]byte("call-id:"),
		[]byte("Call-Id:"),
		[]byte("i:"),
	}
)

// ExtractCID extracts Call-ID from SIP and caches RTCP IP:port mappings from SDP
func ExtractCID(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) {
	srcIPb := []byte(srcIP.String())

	// Find header separator
	posHeaderEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if posHeaderEnd < 0 {
		return
	}

	headers := payload[:posHeaderEnd+4]
	content := payload[posHeaderEnd+4:]

	// Check for SDP content
	contentType, err := getHeaderValue(contentTypeHeaderNames, headers)
	if err != nil {
		return
	}

	multipart := false
	if !bytes.HasPrefix(contentType, []byte("application/sdp")) {
		if !bytes.HasPrefix(contentType, []byte("multipart/")) {
			return
		}
		multipart = true
		if !bytes.Contains(payload, []byte("application/sdp")) {
			return
		}
	}

	// Get Call-ID
	callID, err := getHeaderValue(callIdHeaderNames, headers)
	if err != nil || len(callID) == 0 {
		log.Debug().Msg("No Call-ID found in SIP message")
		return
	}

	// Parse SDP
	var sessionIP []byte
	var rtcpIP []byte
	var rtcpPort []byte
	var rtpPort []byte
	var rtcpMux bool
	session := true

	posLine := 0
	for posLine < len(content) {
		posLineEnd := posLine + bytes.Index(content[posLine:], []byte("\n"))
		if posLineEnd < posLine {
			posLineEnd = len(content)
		}

		line := content[posLine:posLineEnd]
		if bytes.HasSuffix(line, []byte("\r")) {
			line = line[:len(line)-1]
		}
		posLine = posLineEnd + 1

		// Skip non-SDP lines
		if len(line) < 2 || line[1] != '=' {
			if !multipart {
				log.Debug().Str("line", string(line)).Msg("Skipping non-SDP line")
			}
			continue
		}

		switch line[0] {
		case 'c':
			// Connection line: "c=IN IP4 1.1.1.1" or "c=IN IP6 1111::"
			if !bytes.HasPrefix(line, []byte("c=IN IP")) || len(line) < 16 {
				continue
			}
			ip := line[9:]
			if sep := bytes.Index(ip, []byte("/")); sep > 0 {
				ip = ip[:sep]
			}
			if session {
				sessionIP = ip
			} else {
				rtcpIP = ip
			}

		case 'm':
			// Media line
			session = false
			// Add keys for previous media
			if len(rtcpIP) > 0 && len(rtcpPort) > 0 {
				cacheCID(srcIPb, rtcpIP, rtcpPort, callID)
			}
			// RFC 5761: if rtcp-mux was active for previous media, also cache the RTP port
			if rtcpMux && len(rtcpIP) > 0 && len(rtpPort) > 0 && string(rtpPort) != string(rtcpPort) {
				cacheCID(srcIPb, rtcpIP, rtpPort, callID)
			}
			// Reset for new media
			rtcpIP = sessionIP
			rtcpPort = nil
			rtpPort = nil
			rtcpMux = false

			// Only interested in audio
			if !bytes.HasPrefix(line, []byte("m=audio ")) {
				continue
			}

			// Extract RTP port
			sep := bytes.Index(line[8:], []byte(" "))
			if sep < 1 {
				continue
			}
			rtpPortSlice := line[8 : 8+sep]
			if sep2 := bytes.Index(rtpPortSlice, []byte("/")); sep2 > 0 {
				rtpPortSlice = rtpPortSlice[:sep2]
			}

			// Convert RTP port to RTCP port (+1)
			rtpPortNb, err := strconv.Atoi(string(rtpPortSlice))
			if err != nil {
				continue
			}
			rtpPort = []byte(string(rtpPortSlice))
			rtcpPort = []byte(strconv.Itoa(rtpPortNb + 1))

		case 'a':
			// RFC 5761: if rtcp-mux is indicated, RTCP can appear on the RTP port
			if bytes.HasPrefix(line, []byte("a=rtcp-mux")) {
				rtcpMux = true
				continue
			}
			// Attribute line - check for a=rtcp
			if !bytes.HasPrefix(line, []byte("a=rtcp:")) {
				continue
			}

			sep := bytes.Index(line[7:], []byte(" "))
			if sep < 0 {
				// Port only
				rtcpPort = line[7:]
			} else {
				// Port and IP
				if !bytes.HasPrefix(line[7+sep+1:], []byte("IN IP")) {
					continue
				}
				rtcpPort = line[7 : 7+sep]
				if sep2 := bytes.Index(rtcpPort, []byte("/")); sep2 > 0 {
					rtcpPort = rtcpPort[:sep2]
				}
				rtcpIP = line[7+sep+1+5+2:]
				if sep3 := bytes.Index(rtcpIP, []byte("/")); sep3 > 0 {
					rtcpIP = rtcpIP[:sep3]
				}
			}
		}
	}

	// Add keys for last media
	if len(rtcpIP) > 0 && len(rtcpPort) > 0 {
		cacheCID(srcIPb, rtcpIP, rtcpPort, callID)
	}
	// RFC 5761: if rtcp-mux was active for last media, also cache the RTP port
	if rtcpMux && len(rtcpIP) > 0 && len(rtpPort) > 0 && string(rtpPort) != string(rtcpPort) {
		cacheCID(srcIPb, rtcpIP, rtpPort, callID)
	}
}

// cacheCID adds IP:port -> Call-ID mapping to cache
func cacheCID(srcIP, rtcpIP, rtcpPort, callID []byte) {
	key := string(rtcpIP) + " " + string(rtcpPort)
	log.Debug().Str("key", key).Str("callID", string(callID)).Msg("Caching CID")
	cidCache.Set(key, callID)

	// Also add source IP if different
	if !bytes.Equal(rtcpIP, srcIP) {
		key2 := string(srcIP) + " " + string(rtcpPort)
		log.Debug().Str("key", key2).Str("callID", string(callID)).Msg("Caching CID (srcIP)")
		cidCache.Set(key2, callID)
	}
}

// CorrelateRTCP tries to correlate RTCP packet with SIP session.
// Returns (jsonRTCP, correlationID, mos×100).
func CorrelateRTCP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) ([]byte, []byte, uint16) {
	ssrcBytes, jsonRTCP, mos := ParseRTCP(payload)
	if jsonRTCP == nil {
		return nil, nil, 0
	}

	srcKey := srcIP.String() + " " + strconv.Itoa(int(srcPort))
	rtcpKey := srcKey + " " + string(ssrcBytes)

	if corrID, ok := rtcpCache.Get(rtcpKey); ok {
		log.Debug().Str("key", rtcpKey).Str("corrID", string(corrID)).Msg("Found RTCP correlation in rtcpCache")
		return jsonRTCP, corrID, mos
	}

	if corrID, ok := cidCache.Get(srcKey); ok {
		log.Debug().Str("key", srcKey).Str("corrID", string(corrID)).Msg("Found RTCP correlation in cidCache (src)")
		rtcpCache.Set(rtcpKey, corrID)
		return jsonRTCP, corrID, mos
	}

	dstKey := dstIP.String() + " " + strconv.Itoa(int(dstPort))
	if corrID, ok := cidCache.Get(dstKey); ok {
		log.Debug().Str("key", dstKey).Str("corrID", string(corrID)).Msg("Found RTCP correlation in cidCache (dst)")
		rtcpCache.Set(rtcpKey, corrID)
		return jsonRTCP, corrID, mos
	}

	log.Debug().
		Str("srcIP", srcIP.String()).
		Uint16("srcPort", srcPort).
		Str("dstIP", dstIP.String()).
		Uint16("dstPort", dstPort).
		Msg("No RTCP correlation found")

	return nil, nil, 0
}

// getHeaderValue extracts a header value from SIP headers
func getHeaderValue(headerNames [][]byte, headers []byte) ([]byte, error) {
	for _, name := range headerNames {
		pos := bytes.Index(headers, name)
		if pos < 0 {
			continue
		}

		// Find end of line
		rest := headers[pos+len(name):]
		endPos := bytes.Index(rest, []byte("\r\n"))
		if endPos < 0 {
			endPos = len(rest)
		}

		value := bytes.TrimSpace(rest[:endPos])
		return value, nil
	}
	return nil, bytes.ErrTooLarge
}
