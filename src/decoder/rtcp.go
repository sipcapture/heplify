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

// rtcpPacketJSON mirrors heplify v1.67.1 protos/rtcp.go RTCP_Packet JSON shape.
type rtcpPacketJSON struct {
	SenderInformation struct {
		Ntp_timestamp_MSW uint32 `json:"ntp_timestamp_sec"`
		Ntp_timestamp_LSW uint32 `json:"ntp_timestamp_usec"`
		Rtp_timestamp     uint32 `json:"rtp_timestamp"`
		Pkt_count         uint32 `json:"packets"`
		Octet_count       uint32 `json:"octets"`
	} `json:"sender_information"`
	Ssrc           uint32                `json:"ssrc"`
	Type           uint8                 `json:"type"`
	ReportCount    uint8                 `json:"report_count"`
	ReportBlocks   []rtcpReportBlockJSON `json:"report_blocks"`
	ReportBlocksXr rtcpReportBlockXrJSON `json:"report_blocks_xr"`
	// VoIPMetrics is full RFC 3611 VoIP Metrics (BT=7) — extension beyond v1 flat report_blocks_xr.
	VoIPMetrics *rtcpVoIPMetricsJSON `json:"voip_metrics,omitempty"`
	Sdes_ssrc   uint32               `json:"sdes_ssrc"`
}

// rtcpVoIPMetricsJSON holds all fields from RTCP XR VoIP Metrics block (RFC 3611, block type 7).
type rtcpVoIPMetricsJSON struct {
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
	RXConfig       uint8   `json:"rx_config,omitempty"`
	JBNominal      uint16  `json:"jb_nominal,omitempty"`
	JBMaximum      uint16  `json:"jb_maximum,omitempty"`
	JBAbsMax       uint16  `json:"jb_abs_max,omitempty"`
}

type rtcpReportBlockJSON struct {
	SourceSsrc      uint32 `json:"source_ssrc"`
	Fraction_lost   uint8  `json:"fraction_lost"`
	Cumulative_lost uint32 `json:"packets_lost"`
	Highest_seq_no  uint32 `json:"highest_seq_no"`
	Jitter          uint32 `json:"ia_jitter"`
	LastSR          uint32 `json:"lsr"`
	Delay_last_SR   uint32 `json:"dlsr"`
}

type rtcpReportBlockXrJSON struct {
	Type             uint8  `json:"type"`
	ID               uint32 `json:"id"`
	Fraction_lost    uint8  `json:"fraction_lost"`
	Fraction_discard uint8  `json:"fraction_discard"`
	Burst_density    uint8  `json:"burst_density"`
	Gap_density      uint8  `json:"gap_density"`
	Burst_duration   uint16 `json:"burst_duration"`
	Gap_duration     uint16 `json:"gap_duration"`
	Round_trip_delay uint16 `json:"round_trip_delay"`
	End_system_delay uint16 `json:"end_system_delay"`
}

// rxReport is an internal RR/SR report block with optional MOS estimate for HEP MOS chunk.
type rxReport struct {
	SourceSsrc     uint32
	FractionLost   uint8
	CumulativeLost uint32
	HighestSeqNo   uint32
	Jitter         uint32
	LastSR         uint32
	DelayLastSR    uint32
	MOS            float64
}

// ParseRTCP parses RTCP packet and returns SSRC bytes, JSON representation and MOS×100.
// JSON matches heplify v1.67.1 RTCP_Packet wire format.
func ParseRTCP(data []byte) (ssrcBytes []byte, jsonData []byte, mos uint16) {
	if len(data) < 8 {
		return nil, nil, 0
	}

	header := parseRTCPHeader(data)
	if header.Version != 2 {
		return nil, nil, 0
	}

	var pkt rtcpPacketJSON
	var ssrc uint32
	var rxBlocks []rxReport

	switch header.PacketType {
	case RTCPTypeSR:
		if len(data) < 28 {
			return nil, nil, 0
		}
		pkt.Type = RTCPTypeSR
		pkt.ReportCount = header.ReportCount
		ssrc = binary.BigEndian.Uint32(data[4:8])
		pkt.Ssrc = ssrc
		pkt.SenderInformation.Ntp_timestamp_MSW = binary.BigEndian.Uint32(data[8:12])
		pkt.SenderInformation.Ntp_timestamp_LSW = binary.BigEndian.Uint32(data[12:16])
		pkt.SenderInformation.Rtp_timestamp = binary.BigEndian.Uint32(data[16:20])
		pkt.SenderInformation.Pkt_count = binary.BigEndian.Uint32(data[20:24])
		pkt.SenderInformation.Octet_count = binary.BigEndian.Uint32(data[24:28])

		offset := 28
		for i := 0; i < int(header.ReportCount) && offset+24 <= len(data); i++ {
			rr := parseReceiverReportBlock(data[offset:])
			rxBlocks = append(rxBlocks, rr)
			pkt.ReportBlocks = append(pkt.ReportBlocks, rxReportToJSON(rr))
			offset += 24
		}

	case RTCPTypeRR:
		if len(data) < 8 {
			return nil, nil, 0
		}
		pkt.Type = RTCPTypeRR
		pkt.ReportCount = header.ReportCount
		ssrc = binary.BigEndian.Uint32(data[4:8])
		pkt.Ssrc = ssrc

		offset := 8
		for i := 0; i < int(header.ReportCount) && offset+24 <= len(data); i++ {
			rr := parseReceiverReportBlock(data[offset:])
			rxBlocks = append(rxBlocks, rr)
			pkt.ReportBlocks = append(pkt.ReportBlocks, rxReportToJSON(rr))
			offset += 24
		}

	case RTCPTypeSDES:
		pkt.Type = RTCPTypeSDES
		pkt.ReportCount = header.ReportCount
		if len(data) >= 8 {
			pkt.Sdes_ssrc = binary.BigEndian.Uint32(data[4:8])
			ssrc = pkt.Sdes_ssrc
		}

	case RTCPTypeXR:
		if len(data) < 8 {
			return nil, nil, 0
		}
		pkt.Type = RTCPTypeXR
		pkt.ReportCount = header.ReportCount
		ssrc = binary.BigEndian.Uint32(data[4:8])
		pkt.Ssrc = ssrc

		offset := 8
		for offset+4 <= len(data) {
			blockType := data[offset]
			blockLen := int(binary.BigEndian.Uint16(data[offset+2:offset+4])+1) * 4
			if offset+blockLen > len(data) {
				break
			}
			if blockType == 7 && blockLen >= 20 {
				blk := data[offset : offset+blockLen]
				if xr := parseXRBlockV1(blk); xr != nil {
					pkt.ReportBlocksXr = *xr
				}
				if vm := parseVoIPMetricsBlockFull(blk); vm != nil {
					pkt.VoIPMetrics = vm
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

	mos = extractMOS(pkt.VoIPMetrics, rxBlocks)

	out, err := json.Marshal(pkt)
	if err != nil {
		return []byte(fmt.Sprintf("%08x", ssrc)), nil, mos
	}

	return []byte(fmt.Sprintf("%08x", ssrc)), out, mos
}

func rxReportToJSON(rr rxReport) rtcpReportBlockJSON {
	return rtcpReportBlockJSON{
		SourceSsrc:      rr.SourceSsrc,
		Fraction_lost:   rr.FractionLost,
		Cumulative_lost: rr.CumulativeLost,
		Highest_seq_no:  rr.HighestSeqNo,
		Jitter:          rr.Jitter,
		LastSR:          rr.LastSR,
		Delay_last_SR:   rr.DelayLastSR,
	}
}

// parseXRBlockV1 fills report_blocks_xr like v1.67.1 for VoIP Metrics block (RFC 3611, BT=7).
// block begins at the extended report block header (BT, reserved, length).
func parseXRBlockV1(block []byte) *rtcpReportBlockXrJSON {
	if len(block) < 20 || block[0] != 7 {
		return nil
	}
	return &rtcpReportBlockXrJSON{
		Type:             block[0],
		ID:               binary.BigEndian.Uint32(block[4:8]),
		Fraction_lost:    block[8],
		Fraction_discard: block[9],
		Burst_density:    block[10],
		Gap_density:      block[11],
		Burst_duration:   binary.BigEndian.Uint16(block[12:14]),
		Gap_duration:     binary.BigEndian.Uint16(block[14:16]),
		Round_trip_delay: binary.BigEndian.Uint16(block[16:18]),
		End_system_delay: binary.BigEndian.Uint16(block[18:20]),
	}
}

// parseVoIPMetricsBlockFull parses RFC 3611 VoIP Metrics extended report block (BT=7).
// block starts with block header: BT(1), reserved(1), length(16-bit).
func parseVoIPMetricsBlockFull(block []byte) *rtcpVoIPMetricsJSON {
	if len(block) < 28 || block[0] != 7 {
		return nil
	}
	vm := &rtcpVoIPMetricsJSON{
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

func extractMOS(vm *rtcpVoIPMetricsJSON, rxBlocks []rxReport) uint16 {
	if vm != nil && vm.MOSCQ > 0 {
		return uint16(vm.MOSCQ * 100)
	}
	if len(rxBlocks) > 0 && rxBlocks[0].MOS > 0 {
		return uint16(rxBlocks[0].MOS * 100)
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

func parseReceiverReportBlock(data []byte) rxReport {
	var cumBuf [4]byte
	copy(cumBuf[1:], data[5:8])
	cumLost := binary.BigEndian.Uint32(cumBuf[:])

	rr := rxReport{
		SourceSsrc:     binary.BigEndian.Uint32(data[0:4]),
		FractionLost:   data[4],
		CumulativeLost: cumLost,
		HighestSeqNo:   binary.BigEndian.Uint32(data[8:12]),
		Jitter:         binary.BigEndian.Uint32(data[12:16]),
		LastSR:         binary.BigEndian.Uint32(data[16:20]),
		DelayLastSR:    binary.BigEndian.Uint32(data[20:24]),
	}

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
