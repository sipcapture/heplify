package decoder

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
)

const (
	// DiameterHeaderLen is the fixed Diameter message header size (RFC 6733).
	DiameterHeaderLen = 20
	// HEPProtoDiameter is the HEP protocol type used by Captagent/hepagent/Homer.
	HEPProtoDiameter byte = 56
)

// DiameterAVP is one decoded Attribute-Value Pair in the JSON report.
type DiameterAVP struct {
	Code     uint32      `json:"code"`
	Name     string      `json:"name,omitempty"`
	VendorID uint32      `json:"vendor_id,omitempty"`
	Vendor   string      `json:"vendor,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}

// DiameterReport is the JSON representation sent as HEP payload.
type DiameterReport struct {
	Command         uint32        `json:"command,omitempty"`
	CommandName     string        `json:"command_name,omitempty"`
	CommandFlags    uint8         `json:"command-flags,omitempty"`
	Type            string        `json:"type,omitempty"`
	ApplicationID   uint32        `json:"app-ID,omitempty"`
	ApplicationName string        `json:"app-name,omitempty"`
	HopByHopID      string        `json:"hop-by-hop-ID,omitempty"`
	EndToEndID      string        `json:"end-to-end-ID,omitempty"`
	AVPs            []DiameterAVP `json:"avps,omitempty"`
}

// DiameterMessage is one parsed Diameter message ready for HEP.
type DiameterMessage struct {
	JSON []byte
	CID  []byte
}

// IsDiameterPayload reports whether buf looks like a Diameter message header.
func IsDiameterPayload(buf []byte) bool {
	if len(buf) < DiameterHeaderLen || buf[0] != 0x01 {
		return false
	}
	msgLen := int(binary.BigEndian.Uint32(buf[0:4]) & 0x00ffffff)
	return msgLen >= DiameterHeaderLen
}

// DiameterMessageLength returns the Length field from a Diameter header, or 0.
func DiameterMessageLength(buf []byte) int {
	if len(buf) < 4 || buf[0] != 0x01 {
		return 0
	}
	msgLen := int(binary.BigEndian.Uint32(buf[0:4]) & 0x00ffffff)
	if msgLen < DiameterHeaderLen {
		return 0
	}
	return msgLen
}

// ParseDiameterMessages extracts complete Diameter messages from a payload
// that may contain one or more Length-framed messages (TCP or SCTP DATA).
// Incomplete trailing bytes are ignored (caller should buffer for TCP).
func ParseDiameterMessages(payload []byte) []DiameterMessage {
	var out []DiameterMessage
	buf := payload
	for len(buf) >= DiameterHeaderLen {
		if buf[0] != 0x01 {
			break
		}
		msgLen := DiameterMessageLength(buf)
		if msgLen == 0 || msgLen > len(buf) {
			break
		}
		if msg, ok := parseOneDiameter(buf[:msgLen]); ok {
			out = append(out, msg)
		}
		buf = buf[msgLen:]
	}
	return out
}

// ExtractSCTPDiameterPayloads walks SCTP chunks and returns Diameter payloads
// from non-fragmented DATA chunks (chunk type 0).
func ExtractSCTPDiameterPayloads(sctpPayload []byte) [][]byte {
	var payloads [][]byte
	i := 0
	for i < len(sctpPayload) {
		if i+4 > len(sctpPayload) {
			break
		}
		chunkType := sctpPayload[i]
		chunkLength := int(binary.BigEndian.Uint16(sctpPayload[i+2 : i+4]))
		if chunkLength < 4 {
			break
		}
		if chunkType == 0 && chunkLength > 16 && i+chunkLength <= len(sctpPayload) {
			payloads = append(payloads, sctpPayload[i+16:i+chunkLength])
		}
		i += chunkLength
		if i%4 != 0 {
			i += 4 - (i % 4)
		}
	}
	return payloads
}

// ParseDiameterFromPacket parses Diameter from a decoded packet payload.
// For SCTP (0x84), DATA chunks are extracted first.
func ParseDiameterFromPacket(protocol uint8, payload []byte) []DiameterMessage {
	if len(payload) == 0 {
		return nil
	}
	if protocol == 0x84 {
		var out []DiameterMessage
		for _, chunk := range ExtractSCTPDiameterPayloads(payload) {
			out = append(out, ParseDiameterMessages(chunk)...)
		}
		// Some stacks expose only the DATA payload already; try direct parse.
		if len(out) == 0 {
			out = ParseDiameterMessages(payload)
		}
		return out
	}
	return ParseDiameterMessages(payload)
}

func parseOneDiameter(payload []byte) (DiameterMessage, bool) {
	if len(payload) < DiameterHeaderLen || payload[0] != 0x01 {
		return DiameterMessage{}, false
	}

	commandFlags := payload[4]
	commandCode := binary.BigEndian.Uint32(payload[4:8]) & 0x00ffffff
	applicationID := binary.BigEndian.Uint32(payload[8:12])
	hopByHop := binary.BigEndian.Uint32(payload[12:16])
	endToEnd := binary.BigEndian.Uint32(payload[16:20])

	report := DiameterReport{
		Command:         commandCode,
		CommandName:     diameterCommandName(commandCode),
		CommandFlags:    commandFlags,
		Type:            diameterCommandFlagsName(commandFlags),
		ApplicationID:   applicationID,
		ApplicationName: diameterApplicationName(applicationID),
		HopByHopID:      sprintfHex32(hopByHop),
		EndToEndID:      sprintfHex32(endToEnd),
	}

	var sessionID string
	avpData := payload[DiameterHeaderLen:]
	for len(avpData) >= 8 {
		code := binary.BigEndian.Uint32(avpData[0:4])
		flags := avpData[4]
		length := uint32(avpData[5])<<16 | uint32(avpData[6])<<8 | uint32(avpData[7])
		if length < 8 || int(length) > len(avpData) {
			break
		}
		vendorID := uint32(0)
		payloadStart := 8
		hasVendor := flags&0x80 != 0
		if hasVendor {
			if length < 12 {
				break
			}
			vendorID = binary.BigEndian.Uint32(avpData[8:12])
			payloadStart = 12
		}
		raw := avpData[payloadStart:length]

		var data interface{}
		if isGroupedAVP(code) {
			data = map[string]interface{}{"avps": parseGroupedAVPs(raw)}
		} else {
			data = decodeDiameterAVPData(code, raw)
		}
		if code == 263 {
			if s, ok := data.(string); ok {
				sessionID = s
			}
		}

		avp := DiameterAVP{
			Code:     code,
			Name:     diameterAVPName(code),
			VendorID: vendorID,
			Data:     data,
		}
		if hasVendor {
			avp.Vendor = diameterVendorName(vendorID)
		}
		report.AVPs = append(report.AVPs, avp)

		pad := length
		if pad%4 != 0 {
			pad += 4 - (pad % 4)
		}
		avpData = avpData[pad:]
	}

	js, err := json.Marshal(report)
	if err != nil {
		return DiameterMessage{}, false
	}
	msg := DiameterMessage{JSON: js}
	if sessionID != "" {
		msg.CID = []byte(sessionID)
	} else {
		msg.CID = []byte("unknown")
	}
	return msg, true
}

func parseGroupedAVPs(data []byte) []DiameterAVP {
	var avps []DiameterAVP
	buf := data
	for len(buf) >= 8 {
		code := binary.BigEndian.Uint32(buf[0:4])
		flags := buf[4]
		length := uint32(buf[5])<<16 | uint32(buf[6])<<8 | uint32(buf[7])
		if length < 8 || int(length) > len(buf) {
			break
		}
		vendorID := uint32(0)
		payloadStart := 8
		hasVendor := flags&0x80 != 0
		if hasVendor {
			if length < 12 {
				break
			}
			vendorID = binary.BigEndian.Uint32(buf[8:12])
			payloadStart = 12
		}
		raw := buf[payloadStart:length]
		var decoded interface{}
		if isGroupedAVP(code) {
			decoded = map[string]interface{}{"avps": parseGroupedAVPs(raw)}
		} else {
			decoded = decodeDiameterAVPData(code, raw)
		}
		avp := DiameterAVP{
			Code:     code,
			Name:     diameterAVPName(code),
			VendorID: vendorID,
			Data:     decoded,
		}
		if hasVendor {
			avp.Vendor = diameterVendorName(vendorID)
		}
		avps = append(avps, avp)
		pad := length
		if pad%4 != 0 {
			pad += 4 - (pad % 4)
		}
		buf = buf[pad:]
	}
	return avps
}

func decodeDiameterAVPData(code uint32, raw []byte) interface{} {
	switch code {
	case 257: // Host-IP-Address
		if len(raw) >= 6 {
			addrType := binary.BigEndian.Uint16(raw[0:2])
			if addrType == 1 && len(raw) >= 6 {
				return net.IP(raw[2:6]).String()
			}
			if addrType == 2 && len(raw) >= 18 {
				return net.IP(raw[2:18]).String()
			}
		}
		return base64.StdEncoding.EncodeToString(raw)
	case 265: // Supported-Vendor-Id list
		ids := make([]uint32, 0, len(raw)/4)
		for i := 0; i+4 <= len(raw); i += 4 {
			ids = append(ids, binary.BigEndian.Uint32(raw[i:i+4]))
		}
		return ids
	case 258, 259, 261, 262, 266, 267, 268, 272, 273, 274, 276, 277, 278, 285, 291, 295, 298, 299,
		449, 480, 483, 485, 509, 513, 515, 516, 518, 549, 604, 605, 607,
		613, 614, 616, 623, 624, 627, 629, 630, 1006, 1007, 1008, 1023, 1027, 1028, 1032,
		1046, 1047, 1048, 1068, 1071, 1090, 1091,
		1405, 1406, 1410, 1412, 1417, 1419, 1423, 1424, 1428, 1432, 1438, 1445, 1456, 1615:
		if len(raw) >= 4 {
			return binary.BigEndian.Uint32(raw[:4])
		}
		return nil
	case 1, 2, 13, 263, 264, 269, 280, 281, 282, 283, 292, 293, 294, 296, 493,
		601, 602, 608, 617, 621, 1004, 1016, 1037, 1402, 1403:
		return strings.TrimRight(string(raw), "\x00 ")
	case 22, 334, 600, 606, 609, 610, 701, 1407, 1433, 1447, 1448, 1449, 1450, 1489:
		return raw
	default:
		// Prefer readable UTF-8 when payload is mostly text.
		if looksLikeUTF8String(raw) {
			return strings.TrimRight(string(raw), "\x00 ")
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
}

func looksLikeUTF8String(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0 {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
		printable++
	}
	return printable > 0
}

func isGroupedAVP(code uint32) bool {
	switch code {
	case 260, 279, 284, 297, 486, 510, 603, 612, 615, 618, 628, 706, 1001, 1034, 1040, 1041,
		1083, 1400, 1401, 1408, 1413, 1414, 1429, 1430, 1431, 1435:
		return true
	default:
		return false
	}
}

func sprintfHex32(v uint32) string {
	const hexdigits = "0123456789abcdef"
	var b [10]byte
	b[0], b[1] = '0', 'x'
	for i := 0; i < 8; i++ {
		b[2+i] = hexdigits[(v>>(28-uint(i*4)))&0xf]
	}
	return string(b[:])
}
