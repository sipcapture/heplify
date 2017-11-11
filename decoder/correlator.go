package decoder

import (
	"bytes"
	"strconv"

	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

func (d *Decoder) cacheSDPIPPort(payload []byte) {
	var SDPIP, RTCPPort string
	var callID []byte

	if posSDPIP, posSDPPort := bytes.Index(payload, []byte("c=IN IP4 ")), bytes.Index(payload, []byte("m=audio ")); posSDPIP > 0 && posSDPPort > 0 {
		restIP := payload[posSDPIP:]
		// Minimum IPv4 length "c=IN IP4 1.1.1.1" = 16
		if posRestIP := bytes.Index(restIP, []byte("\r\n")); posRestIP >= 16 {
			SDPIP = string(restIP[len("c=IN IP4 "):bytes.Index(restIP, []byte("\r\n"))])
		} else {
			logp.Warn("Couldn't find end of SDP IP in '%s'", string(restIP))
			return
		}

		if posRTCPPort := bytes.Index(payload, []byte("a=rtcp:")); posRTCPPort > 0 {
			restRTCPPort := payload[posRTCPPort:]
			// Minimum RTCP port length "a=rtcp:1000" = 11
			if posRestRTCPPort := bytes.Index(restRTCPPort, []byte("\r\n")); posRestRTCPPort >= 11 {
				RTCPPort = string(restRTCPPort[len("a=rtcp:"):bytes.Index(restRTCPPort, []byte("\r\n"))])
			} else {
				logp.Warn("Couldn't find end of SDP Port in '%s'", string(restRTCPPort))
				return
			}
		} else {
			restPort := payload[posSDPPort:]
			// Minimum RTCP port length "m=audio 1000" = 12
			if posRestPort := bytes.Index(restPort, []byte(" RTP")); posRestPort >= 12 {
				SDPPort, err := strconv.Atoi(string(restPort[len("m=audio "):bytes.Index(restPort, []byte(" RTP"))]))
				if err != nil {
					logp.Warn("%v", err)
				}
				RTCPPort = strconv.Itoa(SDPPort + 1)
			} else {
				logp.Warn("Couldn't find end of SDP Port in '%s'", string(restPort))
				return
			}
		}

		if posCallID := bytes.Index(payload, []byte("Call-ID: ")); posCallID > 0 {
			restCallID := payload[posCallID:]
			// Minimum Call-ID length "Call-ID: a" = 10
			if posRestCallID := bytes.Index(restCallID, []byte("\r\n")); posRestCallID >= 10 {
				callID = restCallID[len("Call-ID: "):bytes.Index(restCallID, []byte("\r\n"))]
			} else {
				logp.Warn("Couldn't find end of Call-ID in '%s'", string(restCallID))
				return
			}
		} else if posID := bytes.Index(payload, []byte("i: ")); posID > 0 {
			restID := payload[posID:]
			// Minimum Call-ID length "i: a" = 4
			if posRestID := bytes.Index(restID, []byte("\r\n")); posRestID >= 4 {
				callID = restID[len("i: "):bytes.Index(restID, []byte("\r\n"))]
			} else {
				logp.Warn("Couldn't find end of Call-ID in '%s'", string(restID))
				return
			}
		}
		logp.Debug("sdp", "Add to SDPCache key=%s, value=%s", SDPIP+RTCPPort, string(callID))
		d.SDPCache.Add(SDPIP+RTCPPort, callID)
	}
}

func (d *Decoder) correlateRTCP(payload []byte) ([]byte, []byte, byte) {
	jsonRTCP, info := protos.ParseRTCP(payload)
	if info != "" {
		logp.Debug("rtcpfail", "%v, srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s", info, d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort)
		if jsonRTCP == nil {
			return nil, nil, 0
		}
	}

	keySDP := d.FlowSrcIP + d.FlowSrcPort
	keyRTCP := d.FlowSrcIP + d.FlowSrcPort + d.FlowDstIP + d.FlowDstPort

	if corrID, ok := d.SDPCache.Get(keySDP); ok {
		logp.Debug("rtcp", "Found '%s' in SDPCache srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", string(corrID), d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
		d.RTCPCache.Add(keyRTCP, corrID)
		return jsonRTCP, corrID, 5
	} else if corrID, ok := d.RTCPCache.Get(keyRTCP); ok {
		logp.Debug("rtcp", "Found '%s' in RTCPCache srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", string(corrID), d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
		return jsonRTCP, corrID, 5
	}

	logp.Debug("rtcpfail", "Can't find correlationID in cache srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
	return nil, nil, 0
}
