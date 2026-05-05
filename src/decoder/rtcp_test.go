package decoder

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// srMinimal builds a minimal valid RTCP SR (28-byte sender section + no report blocks).
func srMinimal(ssrc uint32) []byte {
	b := make([]byte, 28)
	b[0] = 0x80 // V=2, P=0, RC=0
	b[1] = RTCPTypeSR
	binary.BigEndian.PutUint16(b[2:4], 6) // length in words minus 1 → (28/4)-1 = 6
	binary.BigEndian.PutUint32(b[4:8], ssrc)
	return b
}

func TestParseRTCP_JSONTypeIsNumericPT(t *testing.T) {
	ssrc := uint32(0xd24e3e30)
	data := srMinimal(ssrc)
	_, jsonData, _ := ParseRTCP(data)
	if jsonData == nil {
		t.Fatal("expected JSON body for SR")
	}
	var m map[string]any
	if err := json.Unmarshal(jsonData, &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	rawType, ok := m["type"]
	if !ok {
		t.Fatal("missing type field")
	}
	switch v := rawType.(type) {
	case float64:
		if int(v) != RTCPTypeSR {
			t.Fatalf("type: got %v want %d", v, RTCPTypeSR)
		}
	default:
		t.Fatalf("type must be JSON number, got %T %v", rawType, rawType)
	}

	// v1.67.1 field names: sender_information, ntp_timestamp_sec, packets, octets
	si, ok := m["sender_information"].(map[string]any)
	if !ok {
		t.Fatalf("expected sender_information object, got %T", m["sender_information"])
	}
	for _, k := range []string{"ntp_timestamp_sec", "ntp_timestamp_usec", "rtp_timestamp", "packets", "octets"} {
		if _, ok := si[k]; !ok {
			t.Errorf("sender_information missing key %q", k)
		}
	}
	if m["sender_report"] != nil {
		t.Error("old 2.x key sender_report must not appear")
	}
}

// xrMinimalVoIP builds RTCP XR with one RFC 3611 VoIP Metrics block (BT=7), 36-byte block + HEP-style jb tail.
func xrMinimalVoIP(xrSenderSSRC, voipSSRC uint32, mosCQOctet uint8) []byte {
	const pktLen = 44 // 4 RTCP hdr + 4 XR SSRC + 36 VoIP block
	b := make([]byte, pktLen)
	b[0] = 0x80
	b[1] = RTCPTypeXR
	binary.BigEndian.PutUint16(b[2:4], pktLen/4-1)
	binary.BigEndian.PutUint32(b[4:8], xrSenderSSRC)
	// VoIP metrics extended block at offset 8
	blk := b[8:]
	blk[0] = 7
	blk[1] = 0
	binary.BigEndian.PutUint16(blk[2:4], 36/4-1) // 8 words for 36-byte block
	binary.BigEndian.PutUint32(blk[4:8], voipSSRC)
	blk[26] = mosCQOctet // MOS CQ ×10
	// Optional jitter buffer / RX (needs len ≥ 36 in parser)
	blk[28] = 0x01
	binary.BigEndian.PutUint16(blk[30:32], 50)
	binary.BigEndian.PutUint16(blk[32:34], 120)
	binary.BigEndian.PutUint16(blk[34:36], 200)
	return b
}

func TestParseRTCP_XR_VoIPMetricsBlock(t *testing.T) {
	data := xrMinimalVoIP(0x01020304, 0xaabbccdd, 45) // MOS CQ = 4.5
	_, jsonData, mos := ParseRTCP(data)
	if jsonData == nil {
		t.Fatal("expected JSON for XR")
	}
	var m map[string]any
	if err := json.Unmarshal(jsonData, &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	vm, ok := m["voip_metrics"].(map[string]any)
	if !ok || vm == nil {
		t.Fatalf("expected voip_metrics object, got %T", m["voip_metrics"])
	}
	if vm["ssrc"] == nil {
		t.Fatal("voip_metrics.ssrc missing")
	}
	mosCQ, ok := vm["mos_cq"].(float64)
	if !ok || mosCQ != 4.5 {
		t.Fatalf("mos_cq: got %v want 4.5", vm["mos_cq"])
	}
	if mos != 450 {
		t.Fatalf("HEP MOS×100: got %d want 450", mos)
	}
}
