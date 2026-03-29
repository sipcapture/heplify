package decoder

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// NGReport is the JSON representation of a parsed NG (rtpengine) protocol packet
type NGReport struct {
	CallID string                 `json:"call_id,omitempty"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// ParseNG parses an rtpengine NG (bencode) UDP payload and returns (ssrcBytes, jsonPayload).
// Returns nil if parsing fails or no call-id is found.
func ParseNG(data []byte) ([]byte, []byte) {
	if len(data) < 5 {
		return nil, nil
	}

	// NG format: "<cookie> <bencode-dict>"
	// Find the space separator
	spaceIdx := -1
	for i, b := range data {
		if b == ' ' {
			spaceIdx = i
			break
		}
	}
	if spaceIdx < 0 || spaceIdx+1 >= len(data) {
		return nil, nil
	}

	bencodeData := data[spaceIdx+1:]

	val, _, err := decodeBencode(bencodeData, 0)
	if err != nil {
		return nil, nil
	}

	dict, ok := val.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	report := &NGReport{
		Fields: dict,
	}

	if cid, ok := dict["call-id"]; ok {
		if cidStr, ok := cid.(string); ok {
			report.CallID = cidStr
		}
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		return nil, nil
	}

	var ssrc []byte
	if s, ok := dict["ssrc"]; ok {
		ssrc = []byte(fmt.Sprintf("%v", s))
	}

	return ssrc, jsonData
}

// decodeBencode decodes a bencode value starting at position pos in data.
// Returns the decoded value, the new position, and any error.
func decodeBencode(data []byte, pos int) (interface{}, int, error) {
	if pos >= len(data) {
		return nil, pos, fmt.Errorf("unexpected end of data at pos %d", pos)
	}

	switch {
	case data[pos] == 'i':
		// Integer: i<digits>e
		end := pos + 1
		for end < len(data) && data[end] != 'e' {
			end++
		}
		if end >= len(data) {
			return nil, pos, fmt.Errorf("unterminated integer at pos %d", pos)
		}
		n, err := strconv.ParseInt(string(data[pos+1:end]), 10, 64)
		if err != nil {
			return nil, pos, err
		}
		return n, end + 1, nil

	case data[pos] == 'l':
		// List: l<items>e
		list := make([]interface{}, 0)
		pos++
		for pos < len(data) && data[pos] != 'e' {
			val, newPos, err := decodeBencode(data, pos)
			if err != nil {
				return nil, pos, err
			}
			list = append(list, val)
			pos = newPos
		}
		if pos >= len(data) {
			return nil, pos, fmt.Errorf("unterminated list")
		}
		return list, pos + 1, nil

	case data[pos] == 'd':
		// Dictionary: d<key><value>...e
		dict := make(map[string]interface{})
		pos++
		for pos < len(data) && data[pos] != 'e' {
			// Key must be a string
			key, newPos, err := decodeBencode(data, pos)
			if err != nil {
				return nil, pos, err
			}
			keyStr, ok := key.(string)
			if !ok {
				return nil, pos, fmt.Errorf("dict key is not a string")
			}
			pos = newPos

			val, newPos2, err := decodeBencode(data, pos)
			if err != nil {
				return nil, pos, err
			}
			dict[keyStr] = val
			pos = newPos2
		}
		if pos >= len(data) {
			return nil, pos, fmt.Errorf("unterminated dict")
		}
		return dict, pos + 1, nil

	case data[pos] >= '0' && data[pos] <= '9':
		// String: <length>:<data>
		colon := pos
		for colon < len(data) && data[colon] != ':' {
			colon++
		}
		if colon >= len(data) {
			return nil, pos, fmt.Errorf("missing colon in string at pos %d", pos)
		}
		length, err := strconv.Atoi(string(data[pos:colon]))
		if err != nil {
			return nil, pos, err
		}
		start := colon + 1
		end := start + length
		if end > len(data) {
			return nil, pos, fmt.Errorf("string length %d exceeds data", length)
		}
		return string(data[start:end]), end, nil

	default:
		return nil, pos, fmt.Errorf("unknown bencode type byte %c at pos %d", data[pos], pos)
	}
}
