package protos

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/negbie/heplify/logp"
)

/* RTCP header
			0               1               2               3              4
			0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header      |V=2|P|   RC    |  PT(200-204)  |               length          |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SR:
				0               1               2               3              4
				0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	header      |V=2|P|   RC    |    PT=SR=200  |               length          |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                       SSRC of sender                          |
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	sender      |              NTP timestamp,most significant word              |
	info        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|             NTP timestamp,least significant word              |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                          RTP timestamp                        |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                     sender's packet count                     |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                     sender's octet count                      |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	report      |                     SSRC_1 (SSRC of first source)             |
	block       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  1         | fraction lost |      cumulative number of packets lost        |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|       extended highest sequence number received               |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                       interarrival jitter                     |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                           last SR (LSR)                       |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                     delay since last SR (DLSR)                |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	report      |                     SSRC_2 (SSRC of second source)            |
	block       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  2         :                            ...                                :
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				|                     profile-specific extensions               |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RR：
				0               1               2               3              4
				0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	header      |V=2|P|   RC    |    PT=PR=201  |               length          |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                       SSRC of sender                          |
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	report      |                     SSRC_1 (SSRC of first source)             |
	block       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  1         | fraction lost |      cumulative number of packets lost        |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|       extended highest sequence number received               |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                       interarrival jitter                     |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                           last SR (LSR)                       |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                     delay since last SR (DLSR)                |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	report      |                     SSRC_2 (SSRC of second source)            |
	block       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  2         :                            ...                                :
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				|                     profile-specific extensions               |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

SDES:
				0               1               2               3              4
				0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	header      |V=2|P|   SC    |    PT=SR=202  |               length          |
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

BYE：
				 0               1               2               3              4
				 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	header      |V=2|P|   SC    |    PT=SR=203  |               length          |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                           SSRC/CSRC                           |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				:                              ...                              :
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	(opt)       |    length     |           reason for leaving                ...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 APP:
				0               1               2               3              4
				0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	header      |V=2|P|   SC    |    PT=SR=204  |               length          |
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				|                           SSRC/CSRC                           |
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|                           name (ASCII)                        |
				+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				|                     application-dependent data              ...
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
	Version              uint8  `json:"version"`      // 2 bit
	Padding              uint8  `json:"padding"`      // 1 bit
	ReceptionReportCount uint8  `json:"report_count"` // 5 bit
	PacketType           uint8  `json:"type"`         // 8 bit
	Length               uint16 `json:"length"`       // 16 bit
}

type RTCP_Packet struct {
	SenderInformation struct {
		Ssrc              uint32 `json:"ssrc"`               // 32 bit
		Ntp_timestamp_MSW uint32 `json:"ntp_timestamp_sec"`  // 32 bit
		Ntp_timestamp_LSW uint32 `json:"ntp_timestamp_usec"` // 32 bit
		Rtp_timestamp     uint32 `json:"rtp_timestamp"`      // 32 bit
		Pkt_count         uint32 `json:"packets"`            // 32 bit
		Octet_count       uint32 `json:"octets"`             // 32 bit
	} `json:"sender_information"`
	ReportBlocks []RTCP_report_block `json:"report_blocks"`
}

type RTCP_report_block struct {
	Ssrc            uint32 `json:"source_ssrc"`    // 32 bit
	Fraction_lost   uint8  `json:"fraction_lost"`  // 8 bit
	Cumulative_lost uint32 `json:"packets_lost"`   // 24 bit
	Highest_seq_no  uint32 `json:"highest_seq_no"` // 32 bit
	Jitter          uint32 `json:"ia_jitter"`      // 32 bit
	LastSR          uint32 `json:"lsr"`            // 32 bit
	Delay_last_SR   uint32 `json:"dlsr"`           // 32 bit
	ReportCount     uint8  `json:"report_count"`   // 8 bit
	PacketType      uint8  `json:"type"`           // 8 bit
}

func (rp *RTCP_Packet) AddReportBlock(rb RTCP_report_block) []RTCP_report_block {
	rp.ReportBlocks = append(rp.ReportBlocks, rb)
	return rp.ReportBlocks
}

func (rp *RTCP_Packet) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(*rp)
	return bytes, err
}

func ParseRTCP(data []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, errors.New("No usefull data inside RTCP packet")
	}
	pkt := &RTCP_Packet{}
	var offset int

	for pktLen := len(data); pktLen > 0; {
		if pktLen%4 != 0 || pktLen < 4 {
			return nil, errors.New("Fishy RTCP packet")
		}

		//version := (data[offset] & 0xc0) >> 6
		//padding := (data[offset] & 0x20) >> 5
		receptionReportCount := data[offset] & 0x1f
		packetType := data[offset+1]
		packetLength := binary.BigEndian.Uint16(data[offset+2:])

		offset = offset + 4

		if receptionReportCount < 0 || pktLen < 28 {
			return nil, errors.New("Negative reception report or to small RTCP packet")
		}

		switch packetType {
		case TYPE_RTCP_SR:

			pkt.SenderInformation.Ssrc = binary.BigEndian.Uint32(data[offset:])
			pkt.SenderInformation.Ntp_timestamp_MSW = binary.BigEndian.Uint32(data[offset+4:])
			pkt.SenderInformation.Ntp_timestamp_LSW = binary.BigEndian.Uint32(data[offset+8:])
			pkt.SenderInformation.Rtp_timestamp = binary.BigEndian.Uint32(data[offset+12:])
			pkt.SenderInformation.Pkt_count = binary.BigEndian.Uint32(data[offset+16:])
			pkt.SenderInformation.Octet_count = binary.BigEndian.Uint32(data[offset+20:])
			offset = offset + 24

			if receptionReportCount > 0 {
				tmpReportBlocks := make([]RTCP_report_block, receptionReportCount)
				for i := 0; i < int(receptionReportCount); i++ {
					tmpReportBlocks[i].Ssrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])
					tmpReportBlocks[i].ReportCount = receptionReportCount
					tmpReportBlocks[i].PacketType = packetType
					offset = offset + 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}

		case TYPE_RTCP_RR:
			if receptionReportCount > 0 {
				tmpReportBlocks := make([]RTCP_report_block, receptionReportCount)
				for i := 0; i < int(receptionReportCount); i++ {
					tmpReportBlocks[i].Ssrc = binary.BigEndian.Uint32(data[offset:])
					tmpReportBlocks[i].Fraction_lost = data[offset+4]
					var cumBuf [4]byte
					copy(cumBuf[1:], data[offset+5:offset+8])
					tmpReportBlocks[i].Cumulative_lost = binary.BigEndian.Uint32(cumBuf[:])
					tmpReportBlocks[i].Highest_seq_no = binary.BigEndian.Uint32(data[offset+8:])
					tmpReportBlocks[i].Jitter = binary.BigEndian.Uint32(data[offset+12:])
					tmpReportBlocks[i].LastSR = binary.BigEndian.Uint32(data[offset+16:])
					tmpReportBlocks[i].Delay_last_SR = binary.BigEndian.Uint32(data[offset+20:])
					tmpReportBlocks[i].ReportCount = receptionReportCount
					tmpReportBlocks[i].PacketType = packetType
					offset = offset + 24
					pkt.ReportBlocks = pkt.AddReportBlock(tmpReportBlocks[i])
				}
			}

		case TYPE_RTCP_SDES:
			logp.Debug("rtcp", "Discard RTCP_SDES packet type: %d", packetType)
			pktLen -= int(packetLength) * 4
		case TYPE_RTCP_APP:
			logp.Debug("rtcp", "Discard RTCP_APP packet type: %d", packetType)
			pktLen -= int(packetLength) * 4
		case TYPE_RTCP_BYE:
			logp.Debug("rtcp", "Discard RTCP_BYE packet type: %d", packetType)
			pktLen -= int(packetLength) * 4
		case TYPE_RTCP_XR:
			logp.Debug("rtcp", "Discard RTCP_XR packet type: %d", packetType)
			pktLen -= int(packetLength) * 4
		default:
			logp.Debug("rtcp", "Discard unsupported packet type: %d", packetType)
			pktLen -= int(packetLength) * 4
		}

		pktLen -= offset

	}

	rtcpPkt, err := pkt.MarshalJSON()
	if err != nil {
		return nil, err
	}

	logp.Debug("rtcp", "RTCP json payload:\n%v\n", string(rtcpPkt))
	return rtcpPkt, nil
}
