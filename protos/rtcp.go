package protos

import (
	"encoding/binary"
	"fmt"

	"github.com/segmentio/encoding/json"
)

/* RTCP header
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   RC    |  PT(200-207)  |               length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SR:
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   RC    |    PT=SR=200  |               length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       SSRC of sender                          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|              NTP timestamp,most significant word              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             NTP timestamp,least significant word              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          RTP timestamp                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     sender's packet count                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     sender's octet count                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SSRC_1 (SSRC of first source)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| fraction lost |      cumulative number of packets lost        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       extended highest sequence number received               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       interarrival jitter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           last SR (LSR)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     delay since last SR (DLSR)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SSRC_2 (SSRC of second source)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            ...                                |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                     profile-specific extensions               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RR:
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   RC    |    PT=PR=201  |               length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       SSRC of sender                          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                     SSRC_1 (SSRC of first source)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| fraction lost |      cumulative number of packets lost        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       extended highest sequence number received               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       interarrival jitter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           last SR (LSR)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     delay since last SR (DLSR)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SSRC_2 (SSRC of second source)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
:                            ...                                :
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                     profile-specific extensions               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SDES:
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   SC    |    PT=SR=202  |               length          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                           SSRC/CSRC_1                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SDES items                          |
|                              ...                              |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                           SSRC/CSRC_2                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SDES items                          |
|                              ...                              |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

BYE:
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   SC    |    PT=SR=203  |               length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SSRC/CSRC                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
:                              ...                              |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|    length     |           reason for leaving                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

APP:
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   SC    |    PT=SR=204  |               length          |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                           SSRC/CSRC                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           name (ASCII)                        |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                     application-dependent data                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	TYPE_RTCP_SR   = 200
	TYPE_RTCP_RR   = 201
	TYPE_RTCP_SDES = 202
	TYPE_RTCP_BYE  = 203
	TYPE_RTCP_APP  = 204
	TYPE_RTCP_XR   = 207
)

type RTCP_header struct {
	Version     uint8  `json:"version"`      // 2 bit
	Padding     uint8  `json:"padding"`      // 1 bit
	ReportCount uint8  `json:"report_count"` // 5 bit
	RTCPType    uint8  `json:"type"`
	Length      uint16 `json:"length"`
}

type RTCP_Packet struct {
	SenderInformation struct {
		Ntp_timestamp_MSW uint32 `json:"ntp_timestamp_sec"`
		Ntp_timestamp_LSW uint32 `json:"ntp_timestamp_usec"`
		Rtp_timestamp     uint32 `json:"rtp_timestamp"`
		Pkt_count         uint32 `json:"packets"`
		Octet_count       uint32 `json:"octets"`
	} `json:"sender_information"`
	Ssrc           uint32               `json:"ssrc"`
	Type           uint8                `json:"type"`
	ReportCount    uint8                `json:"report_count"`
	ReportBlocks   []RTCP_report_block  `json:"report_blocks"`
	ReportBlocksXr RTCP_report_block_xr `json:"report_blocks_xr"`
	Sdes_ssrc      uint32               `json:"sdes_ssrc"`
}

type RTCP_report_block struct {
	SourceSsrc      uint32 `json:"source_ssrc"`
	Fraction_lost   uint8  `json:"fraction_lost"`
	Cumulative_lost uint32 `json:"packets_lost"` // 24 bit
	Highest_seq_no  uint32 `json:"highest_seq_no"`
	Jitter          uint32 `json:"ia_jitter"`
	LastSR          uint32 `json:"lsr"`
	Delay_last_SR   uint32 `json:"dlsr"`
}

type RTCP_report_block_xr struct {
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

func (rp *RTCP_Packet) AddReportBlock(rb RTCP_report_block) []RTCP_report_block {
	rp.ReportBlocks = append(rp.ReportBlocks, rb)
	return rp.ReportBlocks
}

func (rp *RTCP_Packet) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(*rp)
	return bytes, err
}

func ParseRTCP(data []byte) ([]byte, []byte, string) {
	curLen := len(data)
	dataLen := len(data)
	if curLen < 28 {
		return nil, nil, fmt.Sprintf("Fishy RTCP curLen=%d in packet:\n% X", curLen, data)
	}

	var ssrcBytes []byte
	var infoMsg string
	pkt := &RTCP_Packet{}
	offset := 0

	for curLen > 0 {
		if curLen < 4 || curLen > 768 || offset > dataLen-4 {
			infoMsg = fmt.Sprintf("Fishy RTCP curLen=%d, offset=%d in packet:\n% X", curLen, offset, data)
			break
		}

		RTCPVersion := int((data[offset] & 0xc0) >> 6)
		RTCPPadding := (data[offset] & 0x20) >> 5
		RTCPReportCount := int(data[offset] & 0x1f)
		RTCPType := int(data[offset+1])
		RTCPLength := int(binary.BigEndian.Uint16(data[offset+2:]) * 4)
		offset += 4

		if RTCPVersion != 2 || RTCPPadding > 1 || RTCPReportCount < 0 || RTCPReportCount > 4 || RTCPType < 200 || RTCPType > 207 || RTCPLength > curLen {
			infoMsg = fmt.Sprintf("Fishy RTCP_Header RTCPVersion=%d, RTCPPadding=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, dataLen=%d, curLen=%d, offset=%d in packet:\n% X",
				RTCPVersion, RTCPPadding, RTCPReportCount, RTCPType, RTCPLength, dataLen, curLen, offset, data)
			break
		}

		pkt.Type = uint8(RTCPType)
		pkt.ReportCount = uint8(RTCPReportCount)

		switch RTCPType {
		case TYPE_RTCP_SR:
			if RTCPLength < 24 || offset+24 > dataLen {
				infoMsg = fmt.Sprintf("Fishy RTCP_SR RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, curLen=%d, offset=%d in packet:\n% X",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, curLen, offset, data)
				break
			}

			ssrcBytes = data[offset : offset+4]
			pkt.Ssrc = binary.BigEndian.Uint32(data[offset:])

			pkt.SenderInformation.Ntp_timestamp_MSW = binary.BigEndian.Uint32(data[offset+4:])
			pkt.SenderInformation.Ntp_timestamp_LSW = binary.BigEndian.Uint32(data[offset+8:])
			pkt.SenderInformation.Rtp_timestamp = binary.BigEndian.Uint32(data[offset+12:])
			pkt.SenderInformation.Pkt_count = binary.BigEndian.Uint32(data[offset+16:])
			pkt.SenderInformation.Octet_count = binary.BigEndian.Uint32(data[offset+20:])
			offset += 24

			tmpReportBlocks := make([]RTCP_report_block, RTCPReportCount)
			for i := 0; i < RTCPReportCount; i++ {
				if RTCPReportCount > 0 && RTCPLength >= 24 && offset+24 <= dataLen && len(data[offset:]) >= 4 {
					tmpReportBlocks[i].SourceSsrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])

					offset += 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}

		case TYPE_RTCP_RR:
			if RTCPLength < 4 || offset+4 > dataLen {
				infoMsg = fmt.Sprintf("Fishy RTCP_RR RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, curLen=%d, offset=%d in packet:\n% X",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, curLen, offset, data)
				break
			}

			ssrcBytes = data[offset : offset+4]
			pkt.Ssrc = binary.BigEndian.Uint32(data[offset:])
			offset += 4

			tmpReportBlocks := make([]RTCP_report_block, RTCPReportCount)
			for i := 0; i < RTCPReportCount; i++ {
				if RTCPReportCount > 0 && RTCPLength >= 24 && offset+24 <= dataLen && len(data[offset:]) >= 4 {
					tmpReportBlocks[i].SourceSsrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])

					offset += 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}

		case TYPE_RTCP_SDES:
			if RTCPLength < 4 || offset+4 > dataLen {
				infoMsg = fmt.Sprintf("Fishy RTCP_SDES RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, curLen=%d, offset=%d in packet:\n% X",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, curLen, offset, data)
				break
			}

			ssrcBytes = data[offset : offset+4]
			pkt.Sdes_ssrc = binary.BigEndian.Uint32(data[offset:])
			offset += RTCPLength

		case TYPE_RTCP_APP:
			infoMsg = fmt.Sprintf("Discard RTCP_APP packet type=%d", RTCPType)
			offset += RTCPLength
		case TYPE_RTCP_BYE:
			infoMsg = fmt.Sprintf("Discard RTCP_BYE packet type=%d", RTCPType)
			offset += RTCPLength
		case TYPE_RTCP_XR:
			if RTCPLength < 8 || offset+8 > dataLen {
				infoMsg = fmt.Sprintf("Fishy RTCP_XR RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, curLen=%d, offset=%d in packet:\n% X",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, curLen, offset, data)
				break
			}

			ssrcBytes = data[offset : offset+4]
			pkt.Ssrc = binary.BigEndian.Uint32(data[offset:])
			pkt.ReportBlocksXr.Type = data[offset+4]

			if pkt.ReportBlocksXr.Type == 7 && RTCPLength >= 24 && offset+24 <= dataLen {
				pkt.ReportBlocksXr.ID = binary.BigEndian.Uint32(data[offset+8:])
				pkt.ReportBlocksXr.Fraction_lost = data[offset+12]
				pkt.ReportBlocksXr.Fraction_discard = data[offset+13]
				pkt.ReportBlocksXr.Burst_density = data[offset+14]
				pkt.ReportBlocksXr.Gap_density = data[offset+15]
				pkt.ReportBlocksXr.Burst_duration = binary.BigEndian.Uint16(data[offset+16:])
				pkt.ReportBlocksXr.Gap_duration = binary.BigEndian.Uint16(data[offset+18:])
				pkt.ReportBlocksXr.Round_trip_delay = binary.BigEndian.Uint16(data[offset+20:])
				pkt.ReportBlocksXr.End_system_delay = binary.BigEndian.Uint16(data[offset+22:])
			}
			offset += RTCPLength
		}
		curLen -= RTCPLength + 4
	}

	rtcpPkt, err := pkt.MarshalJSON()
	if err != nil {
		return ssrcBytes, rtcpPkt, err.Error()
	}

	return ssrcBytes, rtcpPkt, infoMsg
}
