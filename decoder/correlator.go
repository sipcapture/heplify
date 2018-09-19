package decoder

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"

	"github.com/negbie/heplify/protos"
	"github.com/negbie/logp"
)

var ipPort bytes.Buffer

// cacheSDPIPPort will extract the source IP, source Port from SDP body and CallID from SIP header.
// It will do this only for SIP messages which have the strings "c=IN IP4 " and "m=audio " in the SDP body.
// If there is one rtcp attribute in the SDP body it will use it as RTCP port. Otherwise it will add 1 to
// the RTP source port. These data will be used for the SDPCache as key:value pairs.
func cacheSDPIPPort(payload []byte) {
	if posSDPIP := bytes.Index(payload, []byte("c=IN IP")); posSDPIP > 0 {
		if posSDPPort := bytes.Index(payload, []byte("m=audio ")); posSDPPort > 0 {
			ipPort.Reset()
			restIP := payload[posSDPIP:]
			// Minimum IPv4 length of "c=IN IP4 1.1.1.1" = 16
			if posRestIP := bytes.Index(restIP, []byte("\r\n")); posRestIP >= 16 {
				ipPort.Write(restIP[len("c=IN IP")+2 : posRestIP])
			} else {
				logp.Debug("sdp", "No end or fishy SDP IP in '%s'", restIP)
				return
			}

			if posRTCPPort := bytes.Index(payload, []byte("a=rtcp:")); posRTCPPort > 0 {
				restRTCPPort := payload[posRTCPPort:]
				// Minimum RTCP port length of "a=rtcp:1000" = 11
				if posRestRTCPPort := bytes.Index(restRTCPPort, []byte("\r\n")); posRestRTCPPort >= 11 {
					ipPort.Write(restRTCPPort[len("a=rtcp:"):posRestRTCPPort])
				} else {
					logp.Debug("sdp", "No end or fishy SDP RTCP Port in '%s'", restRTCPPort)
					return
				}
			} else {
				restPort := payload[posSDPPort:]
				// Minimum RTCP port length of "m=audio 1000" = 12
				if posRestPort := bytes.Index(restPort, []byte(" RTP")); posRestPort >= 12 {
					ipPort.Write(restPort[len("m=audio "):posRestPort])
					lastNum := len(ipPort.Bytes()) - 1
					ipPort.Bytes()[lastNum] = byte(uint32(ipPort.Bytes()[lastNum]) + 1)
				} else {
					logp.Debug("sdp", "No end or fishy SDP RTP Port in '%s'", restPort)
					return
				}
			}

			var callID []byte
			if posCallID := bytes.Index(payload, []byte("Call-I")); posCallID > 0 {
				restCallID := payload[posCallID:]
				// Minimum Call-ID length of "Call-ID: a" = 10
				if posRestCallID := bytes.Index(restCallID, []byte("\r\n")); posRestCallID >= 10 {
					callID = restCallID[len("Call-ID:"):posRestCallID]
				} else {
					logp.Debug("sdp", "No end or fishy Call-ID in '%s'", restCallID)
					return
				}
			} else if posID := bytes.Index(payload, []byte("i: ")); posID > 0 {
				restID := payload[posID:]
				// Minimum Call-ID length of "i: a" = 4
				if posRestID := bytes.Index(restID, []byte("\r\n")); posRestID >= 4 {
					callID = restID[len("i: "):posRestID]
				} else {
					logp.Debug("sdp", "No end or fishy Call-ID in '%s'", restID)
					return
				}
			} else {
				logp.Warn("No Call-ID in '%s'", payload)
				return
			}

			//logp.Debug("sdp", "Add to SDPCache key=%s, value=%s", ipPort.String(), string(callID))
			err := SDPCache.Set(ipPort.Bytes(), bytes.TrimSpace(callID), 120)
			if err != nil {
				logp.Warn("%v", err)
			}
		}
	}
}

// correlateRTCP will try to correlate RTCP data with SIP messages.
// First it will look inside the longlive RTCPCache with the ssrc as key.
// If it can't find a value it will look inside the shortlive SDPCache with (SDPIP+RTCPPort) as key.
// If it finds a value inside the SDPCache it will add it to the RTCPCache with the ssrc as key.
func correlateRTCP(srcIP net.IP, srcPort uint16, payload []byte) ([]byte, []byte, byte) {
	srcIPString := srcIP.String()
	srcPortString := strconv.Itoa(int(srcPort))
	keySDP := []byte(srcIPString + srcPortString)

	keyRTCP, jsonRTCP, info := protos.ParseRTCP(payload)
	if info != "" {
		logp.Debug("rtcp", "ssrc=%d, srcIP=%s, srcPort=%s, %s", keyRTCP, srcIPString, srcPortString, info)
		if jsonRTCP == nil {
			return nil, nil, 0
		}
	}

	if corrID, err := RTCPCache.Get(keyRTCP); err == nil && keyRTCP != nil {
		logp.Debug("rtcp", "Found '%d:%s' in RTCPCache srcIP=%s, srcPort=%s, payload=%s", keyRTCP, corrID, srcIPString, srcPortString, jsonRTCP)
		return jsonRTCP, corrID, 5
	} else if corrID, err := SDPCache.Get(keySDP); err == nil {
		logp.Debug("rtcp", "Found '%s:%s' in SDPCache srcIP=%s, srcPort=%s, payload=%s", keySDP, corrID, srcIPString, srcPortString, jsonRTCP)
		err = RTCPCache.Set(keyRTCP, corrID, 21600)
		if err != nil {
			logp.Warn("%v", err)
			return nil, nil, 0
		}
		return jsonRTCP, corrID, 5
	}

	logp.Debug("rtcp", "No correlationID for srcIP=%s, srcPort=%s, payload=%s", srcIPString, srcPortString, jsonRTCP)
	return nil, nil, 0
}

func correlateLOG(payload []byte) ([]byte, []byte, byte) {
	var callID []byte
	if posID := bytes.Index(payload, []byte("ID=")); posID > 0 {
		restID := payload[posID:]
		// Minimum Call-ID length of "ID=a" = 4
		if posRestID := bytes.IndexRune(restID, ' '); posRestID >= 4 {
			callID = restID[len("ID="):posRestID]
		} else if len(restID) > 4 && len(restID) < 80 {
			callID = restID[3:]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return nil, nil, 0
		}
		if callID != nil {
			logp.Debug("log", "Found CallID: %s in Logline: '%s'", callID, payload)
			return payload, callID, 100

		}
	} else if posID := bytes.Index(payload, []byte(": [")); posID > 0 {
		restID := payload[posID:]
		if posRestID := bytes.Index(restID, []byte(" port ")); posRestID >= 8 {
			callID = restID[len(": ["):posRestID]
		} else if posRestID := bytes.Index(restID, []byte("]: ")); posRestID >= 4 {
			callID = restID[len(": ["):posRestID]
		} else {
			logp.Debug("log", "No end or fishy Call-ID in '%s'", restID)
			return nil, nil, 0
		}
		if len(callID) > 4 && len(callID) < 80 {
			logp.Debug("log", "Found CallID: %s in Logline: '%s'", callID, payload)
			return payload, callID, 100
		}
	}
	return nil, nil, 0
}

func correlateNG(payload []byte) ([]byte, []byte, byte) {
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
				err = SIPCache.Set(cookie, callid, 10)
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
				if corrID, err := SIPCache.Get(cookie); err == nil {
					logp.Debug("ng", "Found CallID: %s and QOS stats: %s", string(corrID), string(data))
					return data, corrID, 100
				}
			}
		}
	}
	return nil, nil, 0
}
