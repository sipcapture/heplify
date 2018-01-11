package decoder

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/protos"
)

// cacheSDPIPPort will extract the source IP, source Port from SDP body and CallID from SIP header.
// It will do this only for SIP messages which have the strings "c=IN IP4 " and "m=audio " in the SDP body.
// If there is one rtcp attribute in the SDP body it will use it as RTCP port. Otherwise it will add 1 to
// the RTP source port. These data will be used for the SDPCache as key:value pairs.
func (d *Decoder) cacheSDPIPPort(payload []byte) {
	if posSDPIP, posSDPPort := bytes.Index(payload, []byte("c=IN IP")), bytes.Index(payload, []byte("m=audio ")); posSDPIP > 0 && posSDPPort > 0 {
		var SDPIP, RTCPPort string
		var callID []byte

		restIP := payload[posSDPIP:]
		// Minimum IPv4 length of "c=IN IP4 1.1.1.1" = 16
		if posRestIP := bytes.Index(restIP, []byte("\r\n")); posRestIP >= 16 {
			SDPIP = string(restIP[len("c=IN IP")+2 : bytes.Index(restIP, []byte("\r\n"))])
		} else {
			logp.Debug("sdpwarn", "No end or fishy SDP IP in '%s'", string(restIP))
			return
		}

		if posRTCPPort := bytes.Index(payload, []byte("a=rtcp:")); posRTCPPort > 0 {
			restRTCPPort := payload[posRTCPPort:]
			// Minimum RTCP port length of "a=rtcp:1000" = 11
			if posRestRTCPPort := bytes.Index(restRTCPPort, []byte("\r\n")); posRestRTCPPort >= 11 {
				RTCPPort = string(restRTCPPort[len("a=rtcp:"):bytes.Index(restRTCPPort, []byte("\r\n"))])
			} else {
				logp.Debug("sdpwarn", "No end or fishy SDP RTCP Port in '%s'", string(restRTCPPort))
				return
			}
		} else {
			restPort := payload[posSDPPort:]
			// Minimum RTCP port length of "m=audio 1000" = 12
			if posRestPort := bytes.Index(restPort, []byte(" RTP")); posRestPort >= 12 {
				SDPPort, err := strconv.Atoi(string(restPort[len("m=audio "):bytes.Index(restPort, []byte(" RTP"))]))
				if err != nil {
					logp.Warn("%v", err)
				}
				RTCPPort = strconv.Itoa(SDPPort + 1)
			} else {
				logp.Debug("sdpwarn", "No end or fishy SDP RTP Port in '%s'", string(restPort))
				return
			}
		}

		if posCallID := bytes.Index(payload, []byte("Call-ID: ")); posCallID > 0 {
			restCallID := payload[posCallID:]
			// Minimum Call-ID length of "Call-ID: a" = 10
			if posRestCallID := bytes.Index(restCallID, []byte("\r\n")); posRestCallID >= 10 {
				callID = restCallID[len("Call-ID: "):bytes.Index(restCallID, []byte("\r\n"))]
			} else {
				logp.Debug("sdpwarn", "No end or fishy Call-ID in '%s'", string(restCallID))
				return
			}
		} else if posID := bytes.Index(payload, []byte("i: ")); posID > 0 {
			restID := payload[posID:]
			// Minimum Call-ID length of "i: a" = 4
			if posRestID := bytes.Index(restID, []byte("\r\n")); posRestID >= 4 {
				callID = restID[len("i: "):bytes.Index(restID, []byte("\r\n"))]
			} else {
				logp.Debug("sdpwarn", "No end or fishy Call-ID in '%s'", string(restID))
				return
			}
		} else {
			logp.Warn("No Call-ID in '%s'", string(payload))
			return
		}
		logp.Debug("sdp", "Add to SDPCache key=%s, value=%s", SDPIP+RTCPPort, string(callID))
		err := d.SDPCache.Set([]byte(SDPIP+RTCPPort), callID, 120)
		if err != nil {
			logp.Warn("%v", err)
		}
	}
}

func (d *Decoder) cacheCallID(payload []byte) {
	if posInvite, posRegister := bytes.Index(payload, []byte(" INVITE")), bytes.Index(payload, []byte(" REGISTER")); posInvite > 0 || posRegister > 0 {
		var callID []byte
		if posCallID := bytes.Index(payload, []byte("Call-ID: ")); posCallID > 0 {
			restCallID := payload[posCallID:]
			// Minimum Call-ID length of "Call-ID: a" = 10
			if posRestCallID := bytes.Index(restCallID, []byte("\r\n")); posRestCallID >= 10 {
				callID = restCallID[len("Call-ID: "):bytes.Index(restCallID, []byte("\r\n"))]
			} else {
				logp.Debug("sipwarn", "No end or fishy Call-ID in '%s'", string(restCallID))
				return
			}
		} else if posID := bytes.Index(payload, []byte("i: ")); posID > 0 {
			restID := payload[posID:]
			// Minimum Call-ID length of "i: a" = 4
			if posRestID := bytes.Index(restID, []byte("\r\n")); posRestID >= 4 {
				callID = restID[len("i: "):bytes.Index(restID, []byte("\r\n"))]
			} else {
				logp.Debug("sipwarn", "No end or fishy Call-ID in '%s'", string(restID))
				return
			}
		}
		err := d.SIPCache.Set(callID, nil, 2)
		if err != nil {
			logp.Warn("%v", err)
		}
	}
}

// correlateRTCP will try to correlate RTCP data with SIP messages.
// First it will look inside the longlive RTCPCache with the ssrc as key.
// If it can't find a value it will look inside the shortlive SDPCache with (SDPIP+RTCPPort) as key.
// If it finds a value inside the SDPCache it will add it to the RTCPCache with the ssrc as key.
func (d *Decoder) correlateRTCP(payload []byte) ([]byte, []byte, byte) {
	keySDP := []byte(d.FlowSrcIP + d.FlowSrcPort)
	keyRTCP, jsonRTCP, info := protos.ParseRTCP(payload)
	if info != "" {
		logp.Debug("rtcpwarn", "ssrc=%d, srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, %v", keyRTCP, d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, info)
		if jsonRTCP == nil {
			return nil, nil, 0
		}
	}

	if corrID, err := d.RTCPCache.Get(keyRTCP); err == nil && keyRTCP != nil {
		logp.Debug("rtcp", "Found '%d:%s' in RTCPCache srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", keyRTCP, string(corrID), d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
		return jsonRTCP, corrID, 5
	} else if corrID, err := d.SDPCache.Get(keySDP); err == nil {
		logp.Debug("rtcp", "Found '%s:%s' in SDPCache srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", string(keySDP), string(corrID), d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
		err = d.RTCPCache.Set(keyRTCP, corrID, 43200)
		if err != nil {
			logp.Warn("%v", err)
			return nil, nil, 0
		}
		return jsonRTCP, corrID, 5
	}

	logp.Debug("rtcpwarn", "No correlationID for srcIP=%s, srcPort=%s, dstIP=%s, dstPort=%s, payload=%s", d.FlowSrcIP, d.FlowSrcPort, d.FlowDstIP, d.FlowDstPort, string(jsonRTCP))
	return nil, nil, 0
}

func (d *Decoder) correlateLOG(payload []byte) ([]byte, []byte, byte) {
	var callID []byte
	if posID := bytes.Index(payload, []byte("ID=")); posID > 0 {
		restID := payload[posID:]
		// Minimum Call-ID length of "ID=a" = 4
		if posRestID := bytes.Index(restID, []byte(" ")); posRestID >= 4 {
			callID = restID[len("ID="):bytes.Index(restID, []byte(" "))]
		} else if len(restID) >= 8 && len(restID) <= 64 {
			callID = restID[3:]
		} else {
			logp.Debug("logwarn", "No end or fishy Call-ID in '%s'", string(restID))
			return nil, nil, 0
		}
		if callID != nil {
			logp.Debug("log", "Found CallID: %s in Logline: '%s'", string(callID), string(payload))
			return payload, callID, 100

		}
	} else if posID := bytes.Index(payload, []byte(": [")); posID > 0 {
		restID := payload[posID:]
		if posRestID := bytes.Index(restID, []byte(" port ")); posRestID >= 8 {
			callID = restID[len(": ["):bytes.Index(restID, []byte(" port "))]
		} else if posRestID := bytes.Index(restID, []byte("]: ")); posRestID >= 4 {
			callID = restID[len(": ["):bytes.Index(restID, []byte("]: "))]
		} else {
			logp.Debug("logwarn", "No end or fishy Call-ID in '%s'", string(restID))
			return nil, nil, 0
		}
		if len(callID) >= 8 && len(callID) <= 64 {
			logp.Debug("log", "Found CallID: %s in Logline: '%s'", string(callID), string(payload))
			return payload, callID, 100
		}
	}
	return nil, nil, 0
}

func (d *Decoder) correlateNG(payload []byte) ([]byte, []byte, byte) {
	cookie, rawNG, err := unmarshalNG(payload)
	if err != nil {
		logp.Warn("%v", err)
		return nil, nil, 0
	}
	switch rawTypes := rawNG.(type) {
	case map[string]interface{}:
		for rawMapKey, rawMapValue := range rawTypes {
			if rawMapKey == "call-id" {
				callid := rawMapValue.([]byte)
				err = d.SIPCache.Set(cookie, callid, 10)
				if err != nil {
					logp.Warn("%v", err)
					return nil, nil, 0
				}
			}

			if rawMapKey == "SSRC" {
				data, err := json.Marshal(&rawMapValue)
				if err != nil {
					logp.Warn("%v", err)
					return nil, nil, 0
				}
				if corrID, err := d.SIPCache.Get(cookie); err == nil {
					logp.Debug("ng", "Found CallID: %s and QOS stats: %s", string(corrID), string(data))
					return data, corrID, 100
				}
			}
		}
	}
	return nil, nil, 0
}
