package decoder

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// RTCP packet types
const (
	RTCPTypeSR    = 200 // Sender Report
	RTCPTypeRR    = 201 // Receiver Report
	RTCPTypeSDES  = 202 // Source Description
	RTCPTypeBYE   = 203 // Goodbye
	RTCPTypeAPP   = 204 // Application-Defined
	RTCPTypeRTPFB = 205 // Transport Layer Feedback
	RTCPTypePSFB  = 206 // Payload-Specific Feedback
	RTCPTypeXR    = 207 // Extended Reports
)

// RTCPHeader represents RTCP packet header
type RTCPHeader struct {
	Version     uint8
	Padding     bool
	ReportCount uint8
	PacketType  uint8
	Length      uint16
}

// SenderReport represents RTCP Sender Report
type SenderReport struct {
	SSRC        uint32 `json:"ssrc"`
	NTPTimeSec  uint32 `json:"ntp_time_sec"`
	NTPTimeFrac uint32 `json:"ntp_time_frac"`
	RTPTime     uint32 `json:"rtp_time"`
	PacketCount uint32 `json:"packet_count"`
	OctetCount  uint32 `json:"octet_count"`
}

// ReceiverReport represents RTCP Receiver Report block
type ReceiverReport struct {
	SSRC             uint32  `json:"ssrc"`
	FractionLost     uint8   `json:"fraction_lost"`
	PacketsLost      int32   `json:"packets_lost"`
	HighestSeq       uint32  `json:"highest_seq"`
	Jitter           uint32  `json:"jitter"`
	LastSR           uint32  `json:"last_sr"`
	DelaySinceLastSR uint32  `json:"delay_since_last_sr"`
	MOS              float64 `json:"mos,omitempty"`
}

// RTCPReport represents parsed RTCP data
type RTCPReport struct {
	Type           string           `json:"type"`
	SSRC           uint32           `json:"ssrc"`
	SenderReport   *SenderReport    `json:"sender_report,omitempty"`
	ReceiverReport []ReceiverReport `json:"receiver_report,omitempty"`
	SDES           []SDESChunk      `json:"sdes,omitempty"`
	VoIPMetrics    *XRVoIPMetrics   `json:"voip_metrics,omitempty"`
}

// SDESItem represents one RTCP SDES item (RFC 3550 Section 6.5).
type SDESItem struct {
	Type uint8  `json:"type"`
	Name string `json:"name"` // human-readable name for the item type
	Text string `json:"text"`
}

// SDESChunk represents one source description chunk (one SSRC + its items).
type SDESChunk struct {
	SSRC  uint32     `json:"ssrc"`
	Items []SDESItem `json:"items"`
}

// XRVoIPMetrics holds fields from RTCP XR VoIP Metrics block (RFC 3611, block type 7)
type XRVoIPMetrics struct {
	SSRC           uint32  `json:"ssrc"`
	LossRate       uint8   `json:"loss_rate"`
	DiscardRate    uint8   `json:"discard_rate"`
	BurstDensity   uint8   `json:"burst_density"`
	GapDensity     uint8   `json:"gap_density"`
	BurstDuration  uint16  `json:"burst_duration"`
	GapDuration    uint16  `json:"gap_duration"`
	RoundTripDelay uint16  `json:"round_trip_delay"`
	EndSystemDelay uint16  `json:"end_system_delay"`
	SignalLevel    int8    `json:"signal_level"`
	NoiseLevel     int8    `json:"noise_level"`
	RERL           uint8   `json:"rerl"`
	Gmin           uint8   `json:"gmin"`
	RFactor        uint8   `json:"r_factor"`
	ExtRFactor     uint8   `json:"ext_r_factor"`
	MOSCQ          float64 `json:"mos_cq"`
	MOSLQ          float64 `json:"mos_lq"`
	RXConfig       uint8   `json:"rx_config"`
	JBNominal      uint16  `json:"jb_nominal"`
	JBMaximum      uint16  `json:"jb_maximum"`
	JBAbsMax       uint16  `json:"jb_abs_max"`
}

// ParseRTCP parses RTCP packet and returns SSRC bytes, JSON representation and MOS×100.
func ParseRTCP(data []byte) (ssrcBytes []byte, jsonData []byte, mos uint16) {
	if len(data) < 8 {
		return nil, nil, 0
	}

	header := parseRTCPHeader(data)
	if header.Version != 2 {
		return nil, nil, 0
	}

	report := &RTCPReport{}
	var ssrc uint32

	switch header.PacketType {
	case RTCPTypeSR:
		if len(data) < 28 {
			return nil, nil, 0
		}
		report.Type = "SR"
		ssrc = binary.BigEndian.Uint32(data[4:8])
		report.SSRC = ssrc
		report.SenderReport = &SenderReport{
			SSRC:        ssrc,
			NTPTimeSec:  binary.BigEndian.Uint32(data[8:12]),
			NTPTimeFrac: binary.BigEndian.Uint32(data[12:16]),
			RTPTime:     binary.BigEndian.Uint32(data[16:20]),
			PacketCount: binary.BigEndian.Uint32(data[20:24]),
			OctetCount:  binary.BigEndian.Uint32(data[24:28]),
		}
		offset := 28
		for i := 0; i < int(header.ReportCount) && offset+24 <= len(data); i++ {
			rr := parseReceiverReportBlock(data[offset:])
			report.ReceiverReport = append(report.ReceiverReport, rr)
			offset += 24
		}

	case RTCPTypeRR:
		if len(data) < 8 {
			return nil, nil, 0
		}
		report.Type = "RR"
		ssrc = binary.BigEndian.Uint32(data[4:8])
		report.SSRC = ssrc

		offset := 8
		for i := 0; i < int(header.ReportCount) && offset+24 <= len(data); i++ {
			rr := parseReceiverReportBlock(data[offset:])
			report.ReceiverReport = append(report.ReceiverReport, rr)
			offset += 24
		}

	case RTCPTypeSDES:
		report.Type = "SDES"
		// ReportCount = SC (number of SSRC chunks)
		offset := 4
		for i := 0; i < int(header.ReportCount) && offset+4 <= len(data); i++ {
			chunk := SDESChunk{
				SSRC: binary.BigEndian.Uint32(data[offset : offset+4]),
			}
			if ssrc == 0 {
				ssrc = chunk.SSRC
			}
			offset += 4
			chunk.Items = parseSDESItems(data, &offset)
			report.SDES = append(report.SDES, chunk)
		}

	case RTCPTypeXR:
		if len(data) < 8 {
			return nil, nil, 0
		}
		report.Type = "XR"
		ssrc = binary.BigEndian.Uint32(data[4:8])
		report.SSRC = ssrc
		// Parse XR blocks
		offset := 8
		for offset+4 <= len(data) {
			blockType := data[offset]
			blockLen := int(binary.BigEndian.Uint16(data[offset+2:offset+4])+1) * 4
			if offset+blockLen > len(data) {
				break
			}
			if blockType == 7 && blockLen >= 28 { // VoIP Metrics block (RFC 3611)
				vm := parseXRVoIPMetrics(data[offset : offset+blockLen])
				if vm != nil {
					report.VoIPMetrics = vm
				}
			}
			offset += blockLen
		}

	default:
		if len(data) >= 8 {
			ssrc = binary.BigEndian.Uint32(data[4:8])
		}
		return []byte(fmt.Sprintf("%08x", ssrc)), nil, 0
	}

	// Extract best MOS value for HEP chunk (as uint16 × 100)
	mos = extractMOS(report)

	out, err := json.Marshal(report)
	if err != nil {
		return []byte(fmt.Sprintf("%08x", ssrc)), nil, mos
	}

	return []byte(fmt.Sprintf("%08x", ssrc)), out, mos
}

// extractMOS returns the best available MOS value scaled ×100 for the HEP MOS chunk.
// Priority: XR VoIP Metrics MOSCQ > first RR block MOS.
func extractMOS(r *RTCPReport) uint16 {
	if r.VoIPMetrics != nil && r.VoIPMetrics.MOSCQ > 0 {
		return uint16(r.VoIPMetrics.MOSCQ * 100)
	}
	if len(r.ReceiverReport) > 0 && r.ReceiverReport[0].MOS > 0 {
		return uint16(r.ReceiverReport[0].MOS * 100)
	}
	return 0
}

func parseRTCPHeader(data []byte) RTCPHeader {
	return RTCPHeader{
		Version:     (data[0] >> 6) & 0x03,
		Padding:     (data[0] & 0x20) != 0,
		ReportCount: data[0] & 0x1F,
		PacketType:  data[1],
		Length:      binary.BigEndian.Uint16(data[2:4]),
	}
}

func parseReceiverReportBlock(data []byte) ReceiverReport {
	packetsLost := int32(data[5])<<16 | int32(data[6])<<8 | int32(data[7])
	// Sign extend 24-bit to 32-bit
	if packetsLost&0x800000 != 0 {
		packetsLost |= -0x1000000 // equivalent to 0xFF000000 but works with int32
	}

	rr := ReceiverReport{
		SSRC:             binary.BigEndian.Uint32(data[0:4]),
		FractionLost:     data[4],
		PacketsLost:      packetsLost,
		HighestSeq:       binary.BigEndian.Uint32(data[8:12]),
		Jitter:           binary.BigEndian.Uint32(data[12:16]),
		LastSR:           binary.BigEndian.Uint32(data[16:20]),
		DelaySinceLastSR: binary.BigEndian.Uint32(data[20:24]),
	}

	// Calculate simple MOS estimate based on fraction lost
	if rr.FractionLost < 10 {
		rr.MOS = 4.5
	} else if rr.FractionLost < 25 {
		rr.MOS = 4.0
	} else if rr.FractionLost < 50 {
		rr.MOS = 3.5
	} else if rr.FractionLost < 100 {
		rr.MOS = 3.0
	} else {
		rr.MOS = 2.5
	}

	return rr
}

// parseSDESItems reads SDES items from data starting at *offset,
// advancing *offset past the items and their 4-byte-aligned padding.
// Returns when a null (END) item is found or data is exhausted.
func parseSDESItems(data []byte, offset *int) []SDESItem {
	var items []SDESItem
	start := *offset

	for *offset < len(data) {
		itemType := data[*offset]
		*offset++

		if itemType == 0 { // END item
			// advance to next 4-byte boundary relative to start of chunk
			used := *offset - start
			if pad := used % 4; pad != 0 {
				*offset += 4 - pad
			}
			return items
		}

		if *offset >= len(data) {
			break
		}
		length := int(data[*offset])
		*offset++

		if *offset+length > len(data) {
			break
		}
		text := string(data[*offset : *offset+length])
		*offset += length

		items = append(items, SDESItem{
			Type: itemType,
			Name: sdesItemName(itemType),
			Text: text,
		})
	}
	return items
}

// sdesItemName maps SDES item type codes to human-readable names (RFC 3550).
func sdesItemName(t uint8) string {
	switch t {
	case 1:
		return "CNAME"
	case 2:
		return "NAME"
	case 3:
		return "EMAIL"
	case 4:
		return "PHONE"
	case 5:
		return "LOC"
	case 6:
		return "TOOL"
	case 7:
		return "NOTE"
	case 8:
		return "PRIV"
	default:
		return fmt.Sprintf("ITEM%d", t)
	}
}

// block must be at least 28 bytes: 4 bytes header + 4 bytes SSRC + 20 bytes metrics.
func parseXRVoIPMetrics(block []byte) *XRVoIPMetrics {
	if len(block) < 28 {
		return nil
	}
	vm := &XRVoIPMetrics{
		SSRC:           binary.BigEndian.Uint32(block[4:8]),
		LossRate:       block[8],
		DiscardRate:    block[9],
		BurstDensity:   block[10],
		GapDensity:     block[11],
		BurstDuration:  binary.BigEndian.Uint16(block[12:14]),
		GapDuration:    binary.BigEndian.Uint16(block[14:16]),
		RoundTripDelay: binary.BigEndian.Uint16(block[16:18]),
		EndSystemDelay: binary.BigEndian.Uint16(block[18:20]),
		SignalLevel:    int8(block[20]),
		NoiseLevel:     int8(block[21]),
		RERL:           block[22],
		Gmin:           block[23],
		RFactor:        block[24],
		ExtRFactor:     block[25],
		MOSCQ:          float64(block[26]) / 10.0,
		MOSLQ:          float64(block[27]) / 10.0,
	}
	if len(block) >= 36 {
		vm.RXConfig = block[28]
		vm.JBNominal = binary.BigEndian.Uint16(block[30:32])
		vm.JBMaximum = binary.BigEndian.Uint16(block[32:34])
		vm.JBAbsMax = binary.BigEndian.Uint16(block[34:36])
	}
	return vm
}
