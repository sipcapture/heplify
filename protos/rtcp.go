package protos

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

/* RTCP header
0               1               2               3              4
0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|   RC    |  PT(200-204)  |               length          |
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
	RTCPType    uint8  `json:"type"`         // 8 bit
	Length      uint16 `json:"length"`       // 16 bit
}

type RTCP_Packet struct {
	SenderInformation struct {
		Ntp_timestamp_MSW uint32 `json:"ntp_timestamp_sec"`  // 32 bit
		Ntp_timestamp_LSW uint32 `json:"ntp_timestamp_usec"` // 32 bit
		Rtp_timestamp     uint32 `json:"rtp_timestamp"`      // 32 bit
		Pkt_count         uint32 `json:"packets"`            // 32 bit
		Octet_count       uint32 `json:"octets"`             // 32 bit
	} `json:"sender_information"`
	Ssrc         uint32              `json:"ssrc"` // 32 bit
	ReportBlocks []RTCP_report_block `json:"report_blocks"`
}

type RTCP_report_block struct {
	SourceSsrc      uint32 `json:"source_ssrc"`    // 32 bit
	Fraction_lost   uint8  `json:"fraction_lost"`  // 8 bit
	Cumulative_lost uint32 `json:"packets_lost"`   // 24 bit
	Highest_seq_no  uint32 `json:"highest_seq_no"` // 32 bit
	Jitter          uint32 `json:"ia_jitter"`      // 32 bit
	LastSR          uint32 `json:"lsr"`            // 32 bit
	Delay_last_SR   uint32 `json:"dlsr"`           // 32 bit
	ReportCount     uint8  `json:"report_count"`   // 8 bit
	RTCPType        uint8  `json:"type"`           // 8 bit
}

func (rp *RTCP_Packet) AddReportBlock(rb RTCP_report_block) []RTCP_report_block {
	rp.ReportBlocks = append(rp.ReportBlocks, rb)
	return rp.ReportBlocks
}

func (rp *RTCP_Packet) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(*rp)
	return bytes, err
}

func ParseRTCP(data []byte) (rtcpPkt []byte, infoMsg string) {
	dataLen := len(data)
	if dataLen < 28 {
		return nil, fmt.Sprintf("Fishy RTCP dataLen=%d in packet:\n%v", dataLen, hex.Dump(data))
	}
	var err error
	pkt := &RTCP_Packet{}
	offset := 0

	for dataLen > 0 {
		if dataLen < 4 || dataLen > 576 {
			return rtcpPkt, fmt.Sprintf("Fishy RTCP dataLen=%d in packet:\n%v", dataLen, hex.Dump(data))
		}

		RTCPVersion := int((data[offset] & 0xc0) >> 6)
		//padding := (data[offset] & 0x20) >> 5
		RTCPReportCount := int(data[offset] & 0x1f)
		RTCPType := int(data[offset+1])
		RTCPLength := int(binary.BigEndian.Uint16(data[offset+2:]) * 4)
		offset += 4

		if RTCPVersion != 2 || RTCPReportCount < 0 || RTCPReportCount > 4 || RTCPType < 200 || RTCPType > 207 || RTCPLength > dataLen {
			return rtcpPkt, fmt.Sprintf("Fishy RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, dataLen=%d, offset=%d in packet:\n%v",
				RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, dataLen, offset, hex.Dump(data))
		}

		switch RTCPType {
		case TYPE_RTCP_SR:
			if RTCPLength < 24 || offset+24 > len(data) {
				return rtcpPkt, fmt.Sprintf("Fishy RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, dataLen=%d, offset=%d in packet:\n%v",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, dataLen, offset, hex.Dump(data))
			}

			pkt.Ssrc = binary.BigEndian.Uint32(data[offset:])
			pkt.SenderInformation.Ntp_timestamp_MSW = binary.BigEndian.Uint32(data[offset+4:])
			pkt.SenderInformation.Ntp_timestamp_LSW = binary.BigEndian.Uint32(data[offset+8:])
			pkt.SenderInformation.Rtp_timestamp = binary.BigEndian.Uint32(data[offset+12:])
			pkt.SenderInformation.Pkt_count = binary.BigEndian.Uint32(data[offset+16:])
			pkt.SenderInformation.Octet_count = binary.BigEndian.Uint32(data[offset+20:])
			offset += 24

			if RTCPReportCount > 0 && RTCPLength >= 24 && offset+24 <= len(data) {
				tmpReportBlocks := make([]RTCP_report_block, RTCPReportCount)
				for i := 0; i < RTCPReportCount; i++ {
					tmpReportBlocks[i].SourceSsrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])
					tmpReportBlocks[i].ReportCount = uint8(RTCPReportCount)
					tmpReportBlocks[i].RTCPType = uint8(RTCPType)
					offset += 24
					RTCPLength -= 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}
			rtcpPkt, err = pkt.MarshalJSON()
			if err != nil {
				return nil, fmt.Sprintf("RTCP MarshalJSON %v", err)
			}

		case TYPE_RTCP_RR:
			if RTCPLength < 4 || offset+4 > len(data) {
				return rtcpPkt, fmt.Sprintf("Fishy RTCPVersion=%d, RTCPReportCount=%d, RTCPType=%d, RTCPLength=%d, dataLen=%d, offset=%d in packet:\n%v",
					RTCPVersion, RTCPReportCount, RTCPType, RTCPLength, dataLen, offset, hex.Dump(data))
			}

			pkt.Ssrc = binary.BigEndian.Uint32(data[offset:])
			offset += 4

			if RTCPReportCount > 0 && RTCPLength >= 24 && offset+24 <= len(data) {
				tmpReportBlocks := make([]RTCP_report_block, RTCPReportCount)
				for i := 0; i < RTCPReportCount; i++ {
					tmpReportBlocks[i].SourceSsrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])
					tmpReportBlocks[i].ReportCount = uint8(RTCPReportCount)
					tmpReportBlocks[i].RTCPType = uint8(RTCPType)
					offset += 24
					RTCPLength -= 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}
			rtcpPkt, err = pkt.MarshalJSON()
			if err != nil {
				return nil, fmt.Sprintf("RTCP MarshalJSON %v", err)
			}

		case TYPE_RTCP_SDES:
			infoMsg = fmt.Sprintf("Discard RTCP_SDES packet type=%d", RTCPType)
			offset += RTCPLength
		case TYPE_RTCP_APP:
			infoMsg = fmt.Sprintf("Discard RTCP_APP packet type=%d", RTCPType)
			offset += RTCPLength
		case TYPE_RTCP_BYE:
			infoMsg = fmt.Sprintf("Discard RTCP_BYE packet type=%d", RTCPType)
			offset += RTCPLength
		case TYPE_RTCP_XR:
			infoMsg = fmt.Sprintf("Discard RTCP_XR packet type=%d", RTCPType)
			offset += RTCPLength
		}

		dataLen -= offset
	}

	return
}
