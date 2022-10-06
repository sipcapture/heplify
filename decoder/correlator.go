package decoder

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"

	"github.com/negbie/freecache"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/protos"
)

var (
	// cidCache need to be at least large enough for concurrent-calls * RTP-endpoints * entry-size.
	// RTP-endpoints is the average number of RTP endpoints per call, counting endpoints different from SIP source IP twice.
	// entry-size is the average size of one endpoint entry, including textual IP length, textual port length, Call-ID length and one separators.
	// Some guesses: concurrent-calls=1000, number-of-RTP-endpoints=400, entry-size=100.
	cidCache = freecache.NewCache(40 * 1024 * 1024) // 40 MB
	// rtcpCache need to be at least large enough for concurrent-calls * RTCP-endpoints * entry-size.
	// RTCP-endpoints is the average number of used RTCP endpoints per call.
	// entry-size is the average size of one endpoint entry, including textual IP length, textual port length, SSRC-length, Call-ID length and two separators.
	// Some guesses: concurrent-calls=1000, number-of-RTCP-endpoints=400, entry-size=100.
	rtcpCache = freecache.NewCache(40 * 1024 * 1024) // 40 MB
	// cidCacheTime is the maximum time between seeing SDP and seeing the first packets for all associated RTCP streams.
	cidCacheTime = 10 * 60 * 20 // 20 minutes in tenth of a seconds.
	// rtcpCacheTime is the maximum time a RTCP stream may be associated to a call (maximum allowed call time).
	rtcpCacheTime = 10 * 60 * 60 * 12 // 12 hours in tenth of a seconds.
)

// cacheCID will add an entry to cidCache with rtcpIP+rtcpPort as key and callID as value.
// If scrIP is different from rtcpIP a srcIP+rtcpPort key will added too.
//
// If RTCP IP is different from source IP, it may indicate that the source is behind NAT and uses
// internal IP's in SDP. Therefore we add a key with source IP to, in the hope that later RTCP packet
// source IP will be the same as SIP packet source IP. But RTCP and source IP could be different for
// other reasons (e.g. different SIP and RTP endpoints), which would make RTCP IP the correct one.
// As we can not known which is the correct one we add two keys in this case.
// Key parts will be separated by a single space.
func cacheCID(srcIP []byte, rtcpIP []byte, rtcpPort []byte, callID []byte) {
	var buffer [60]byte // use large enough buffer on stack for fast append
	var key []byte
	key = append(append(append(buffer[:0], rtcpIP...), ' '), rtcpPort...)
	if logp.HasSelector("sdp") {
		logp.Debug("sdp", "Add to cidCache key=%q, value=%q", key, callID)
	}
	cidCache.Set(key, callID, cidCacheTime)
	if !bytes.Equal(rtcpIP, srcIP) {
		key = append(append(append(buffer[:0], srcIP...), ' '), rtcpPort...)
		if logp.HasSelector("sdp") {
			logp.Debug("sdp", "Add to cidCache key=%q, value=%q", key, callID)
		}
		cidCache.Set(key, callID, cidCacheTime)
	}
}

// extractCID will extract the Call-ID and all RTCP IP and port combinations will add them to the cidCache,
// with IP+port as key and Call-ID as value.
//
// It will only process payload that has SDP content or multipart content that contains SDP.
// It will only process audio media.
// There must be a Call-ID in the SIP-Headers.
// It will use IP's from source, c lines and a=rtcp lines.
// It will use RTCP ports from m lines (RTP port + 1) or a=rtcp lines.
// It will only use the first address from multi address notation.
// It will only use the first port from multi port notation.
// The function makes some assumptions about the well-formedness of the SDP for faster parsing.
// Key parts will be separated by a single space.
func extractCID(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) {
	// TODO: improve multipart handling.
	var (
		srcIPb      = []byte(srcIP.String()) // source IP as text as bytes.
		contentType []byte                   // Content-Type header value.
		callID      []byte                   // Call-ID header value.
		err         error                    // for error checking.
		multipart   = false                  // is this a multipart content message?
	)

	// Do we have a header separator?
	posHeaderEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if posHeaderEnd < 0 {
		return
	}
	// Split in headers and content
	headers := payload[:posHeaderEnd+4] // keep separator
	content := payload[posHeaderEnd+4:] // strip separator

	// Do we have SDP content?
	contentType, err = getHeaderValue(contentTypeHeaderNames, headers)
	if err != nil {
		// Content-Type only exists if there is content, no need for logging.
		return
	}
	if !bytes.HasPrefix(contentType, []byte("application/sdp")) {
		// Not SDP. It is multipart?
		if !bytes.HasPrefix(contentType, []byte("multipart/")) {
			// Not multipart, nothing to do.
			return
		}
		// It is multipart.
		multipart = true
		// Multipart must contain SDP.
		if bytes.Index(payload, []byte("applicaton/sdp")) < 0 {
			// No SDP, nothing to do.
			return
		}
		logp.Debug("sdp", "Found sdp in multipart message. srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v",
			srcIP, srcPort, dstIP, dstPort)
	}

	// Get Call-ID.
	callID, err = getHeaderValue(callIdHeaderNames, headers)
	if err != nil || len(callID) == 0 {
		logp.Debug("sdp", "No or fishy Call-ID. srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v, headers=%q",
			srcIP, srcPort, dstIP, dstPort, headers)
		return
	}

	// Loop through all content lines.
	// Allow \n and \r\n line separators.
	var (
		posLine    = 0    // start of line.
		posLineEnd = 0    // end of line, position of \n or end of content.
		session    = true // in session or multimedia?
		sessionIP  []byte // IP found in session connection.
		rtcpIP     []byte // IP for RTCP.
		rtcpPort   []byte // port for RTCP.
	)
sdpLoop:
	for posLine = 0; posLine < len(content); posLine = posLineEnd + 1 {
		// Find \n at end of line.
		posLineEnd = posLine + bytes.Index(content[posLine:], []byte("\n"))
		if posLineEnd < posLine {
			posLineEnd = len(content)
		}
		// Get line without line separator, remove \r.
		line := content[posLine:posLineEnd]
		if bytes.HasSuffix(line, []byte("\r")) {
			line = line[:len(line)-1]
		}

		// Skip lines that do not look like SDP.
		if len(line) < 2 || line[1] != '=' {
			// Multipart content contains non SDP lines, do not clutter the log.
			if !multipart {
				logp.Debug("sdp", "Fishy sdp line %q. callID=%q", line, callID)
			}
			continue sdpLoop
		}

		// Process SDP line.
		switch line[0] {
		case 'c':
			// Connection line should contain at least
			// "c=IN IP4 1.1.1.1" or "c=IN IP6 1111::".
			if !bytes.HasPrefix(line, []byte("c=IN IP")) || len(line) < 16 {
				logp.Debug("sdp", "Fishy c= line %q. callID=%q", line, callID)
				continue sdpLoop
			}
			// Extract IP.
			ip := line[9:]
			// Check for and strip ttl/count separated by slash.
			sep := bytes.Index(ip, []byte("/"))
			if sep > 0 {
				ip = ip[:sep]
			}
			// Use as session or RTCP IP.
			if session {
				sessionIP = ip
			} else {
				rtcpIP = ip
			}
		case 'm':
			// Begin new media.
			// No longer session.
			session = false
			// Add keys for previous media.
			if len(rtcpIP) > 0 && len(rtcpPort) > 0 {
				cacheCID(srcIPb, rtcpIP, rtcpPort, callID)
			}
			// Reset RTCP data for this media.
			rtcpIP = sessionIP
			rtcpPort = nil
			// We are only interested in audio.
			if !bytes.HasPrefix(line, []byte("m=audio ")) {
				continue sdpLoop
			}
			// Find separator after RTP port number.
			sep := bytes.Index(line[8:], []byte(" "))
			if sep < 4 { // Port should be above 1000
				logp.Debug("sdp", "Fishy m=audio line %q. callID=%q", line, callID)
				continue sdpLoop
			}
			// Extract RTP port.
			rtpPort := line[8 : 8+sep]
			// Check for and strip port count.
			sep2 := bytes.Index(rtpPort, []byte("/"))
			if sep2 > 0 {
				rtpPort = rtpPort[:sep2]
			}
			// Convert from RTP port to RTCP port by adding 1.
			// Do not assume that RTP port is even.
			rtpPortNb, err2 := strconv.Atoi(string(rtpPort))
			if err2 != nil {
				logp.Debug("sdp", "Fishy m=audio line %q. callID=%q", line, callID)
				continue sdpLoop
			}
			rtcpPort = []byte(strconv.Itoa(rtpPortNb + 1))
		case 'a':
			// We are only interested in a=rtcp.
			if !bytes.HasPrefix(line, []byte("a=rtcp:")) {
				continue sdpLoop
			}
			// May contain only port or port and IP.
			sep := bytes.Index(line[7:], []byte(" "))
			if sep < 0 {
				// Port only.
				rtcpPort = line[7:]
			} else {
				// Port and IP, e.g. "1000 IN IP4 1.1.1.1".
				if !bytes.HasPrefix(line[7+sep+1:], []byte("IN IP")) {
					logp.Debug("sdp", "Fishy a=rtcp line %q. callID=%q", line, callID)
					continue sdpLoop
				}
				// Extract port.
				rtcpPort = line[7 : 7+sep]
				// Check for and strip count.
				sep2 := bytes.Index(rtcpPort, []byte("/"))
				if sep2 > 0 {
					rtcpPort = rtcpPort[:sep2]
				}
				// Extract IP.
				rtcpIP = line[7+sep+1+5+2:] // space + "IN IP" + version + space.
				// Check for and strip ttl/count separated by slash.
				sep3 := bytes.Index(rtcpIP, []byte("/"))
				if sep3 > 0 {
					rtcpIP = rtcpIP[:sep3]
				}
			}
		default:
			// ignore other SDP lines.
		}
	}
	// Add keys for last media.
	if len(rtcpIP) > 0 && len(rtcpPort) > 0 {
		cacheCID(srcIPb, rtcpIP, rtcpPort, callID)
	}
}

// correlateRTCP will try to correlate RTCP data with SIP messages.
// It will return the parsed RTCP JSON and the correlation ID.
//
// First it will look inside the long-lived RTCPCache with the srcIP+srcPort+SSRC as key.
// If it can't find a value it will look inside the short-lived cidCache with srcIP+srcPort or dstIP+dstPort as key.
// If it finds a value inside the cidCache it will add it to the RTCPCache.
// Key parts will be separated by a single space.
func correlateRTCP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) ([]byte, []byte) {
	var corrID = make([]byte, 0, 60)

	// Parse RTCP.
	ssrcBytes, jsonRTCP, info := protos.ParseRTCP(payload)
	if info != "" {
		if logp.HasSelector("rtcp") {
			logp.Debug("rtcp", "Parsing rtcp returned info. ssrc=%x, srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v, info=%q",
				ssrcBytes, srcIP, srcPort, dstIP, dstPort, info)
		}
		if jsonRTCP == nil {
			// Not RTCP or broken RTCP
			return nil, nil
		}
	}

	// Build source IP + port key.
	srcIPString := srcIP.String()
	srcPortString := strconv.Itoa(int(srcPort))
	srcKey := []byte(srcIPString + " " + srcPortString)

	// TODO: this could lead to missing RTCP packets.
	// Build RTCP key for source IP + port + SSRC.
	rtcpKey := bytes.Join([][]byte{srcKey, ssrcBytes}, []byte(" "))

	// Lookup correlation ID with RTCP key.
	corrID, err := rtcpCache.GetWithBuf(rtcpKey, corrID[:0])
	if err == nil && rtcpKey != nil {
		if logp.HasSelector("rtcp") {
			logp.Debug("rtcp", "Found key=%q value=%q in rtcpCache for srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v",
				rtcpKey, corrID, srcIP, srcPort, dstIP, dstPort)
		}
		return jsonRTCP, corrID
	}

	// Lookup correlation ID with RTCP source IP and port and add with RTCP key
	corrID, err = cidCache.GetWithBuf(srcKey, corrID[:0])
	if err == nil {
		if logp.HasSelector("rtcp") {
			logp.Debug("rtcp", "Found key=%q value=%q in cidCache for srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v",
				srcKey, corrID, srcIP, srcPort, dstIP, dstPort)
		}
		err = rtcpCache.Set(rtcpKey, corrID, rtcpCacheTime)
		if err != nil {
			logp.Warn("%v", err)
			return nil, nil
		}
		return jsonRTCP, corrID
	}

	// Build destination IP + port key.
	dstIPString := dstIP.String()
	dstPortString := strconv.Itoa(int(dstPort))
	dstKey := []byte(dstIPString + " " + dstPortString)

	// Lookup correlation ID with RTCP destination IP and port and add with RTCP key
	corrID, err = cidCache.GetWithBuf(dstKey, corrID[:0])
	if err == nil {
		if logp.HasSelector("rtcp") {
			logp.Debug("rtcp", "Found key=%q value=%q in cidCache for srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v",
				dstKey, corrID, srcIP, srcPort, dstIP, dstPort)
		}
		err = rtcpCache.Set(rtcpKey, corrID, rtcpCacheTime)
		if err != nil {
			logp.Warn("%v", err)
			return nil, nil
		}
		return jsonRTCP, corrID
	}

	if logp.HasSelector("rtcp") {
		logp.Debug("rtcp", "No correlationID for srcIP=%v, srcPort=%v, dstIP=%v, dstPort=%v",
			srcIP, srcPort, dstIP, dstPort)
	}
	// Nothing found so return failure.
	return nil, nil
}

func correlateLOG(payload []byte) (byte, []byte) {
	var callID []byte
	if posID := bytes.Index(payload, []byte("ID=«")); posID > 0 {
		restID := payload[posID:]
		// Minimum Call-ID length of "ID=«a" is 5
		if posRestID := bytes.IndexRune(restID, '»'); posRestID >= 5 {
			callID = restID[len("ID=«"):posRestID]
		} else if len(restID) > 5 && len(restID) < 80 {
			callID = restID[len("ID=«"):]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return 0, nil
		}
	} else if posID := bytes.Index(payload, []byte("ID=")); posID > 0 {
		restID := payload[posID:]
		// Minimum Call-ID length of "ID=a" is 4
		if posRestID := bytes.IndexRune(restID, ' '); posRestID >= 4 {
			callID = restID[len("ID="):posRestID]
		} else if len(restID) > 4 && len(restID) < 80 {
			callID = restID[len("ID="):]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return 0, nil
		}
	} else if posID := bytes.Index(payload, []byte(": [«")); posID > 0 {
		restID := payload[posID:]
		if posRestID := bytes.Index(restID, []byte("» port ")); posRestID >= 5 {
			callID = restID[len(": [«"):posRestID]
		} else if posRestID := bytes.Index(restID, []byte("»]: ")); posRestID >= 5 {
			callID = restID[len(": [«"):posRestID]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return 0, nil
		}
	} else if posID := bytes.Index(payload, []byte("INFO: [")); posID > 0 {
		restID := payload[posID:]
		if posRestID := bytes.Index(restID, []byte(" port ")); posRestID >= 8 {
			callID = restID[len("INFO: ["):posRestID]
		} else if posRestID := bytes.Index(restID, []byte("]: ")); posRestID >= 8 {
			callID = restID[len("INFO: ["):posRestID]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return 0, nil
		}
	}
	if len(callID) > 1 && len(callID) < 80 {
		logp.Debug("log", "Found CallID: %s in Logline: '%s'", callID, payload)
		return 100, callID
	}
	return 0, nil
}

func correlateNG(payload []byte) ([]byte, []byte) {
	cookie, rawNG, err := unmarshalNG(payload)
	if err != nil {
		logp.Warn("%v", err)
		return nil, nil
	}
	switch rawTypes := rawNG.(type) {
	case map[string]interface{}:
		for rawMapKey, rawMapValue := range rawTypes {
			if rawMapKey == "call-id" {
				callid := rawMapValue.([]byte)
				err = cidCache.Set(cookie, callid, 100)
				if err != nil {
					logp.Warn("%v", err)
					return nil, nil
				}
			}

			if rawMapKey == "SSRC" {
				data, err := json.Marshal(&rawMapValue)
				if err != nil {
					logp.Warn("%v", err)
					return nil, nil
				}
				if corrID, err := cidCache.Get(cookie); err == nil {
					logp.Debug("ng", "Found CallID: %s and QOS stats: %s", string(corrID), string(data))
					return data, corrID
				}
			}
		}
	}
	return nil, nil
}
