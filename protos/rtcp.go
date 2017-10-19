package protos

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

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
)

type RTCP_header struct {
	Version              uint8  `json:"version"`      // 2 bit
	Padding              uint8  `json:"padding"`      // 1 bit
	ReceptionReportCount uint8  `json:"report_count"` // 5 bit
	PacketType           uint8  `json:"type"`         // 16 bit
	Length               uint16 `json:"length"`       // 16 bit
}

type RTCP_report_block struct {
	Ssrc            uint32 `json:"source_ssrc"`    // 32 bit
	Fraction_lost   uint8  `json:"fraction_lost"`  // 8 bit
	Cumulative_lost uint32 `json:"packets_lost"`   // 24 bit
	Highest_seq_no  uint32 `json:"highest_seq_no"` // 32 bit
	Jitter          uint32 `json:"ia_jitter"`      // 32 bit
	LastSR          uint32 `json:"lsr"`            // 32 bit
	Delay_last_SR   uint32 `json:"dlsr"`           // 32 bit
}

type RTCP_SR struct {
	Ssrc              uint32              `json:"ssrc"`               // 32 bit
	Ntp_timestamp_MSW uint32              `json:"ntp_timestamp_sec"`  // 32 bit
	Ntp_timestamp_LSW uint32              `json:"ntp_timestamp_usec"` // 32 bit
	Rtp_timestamp     uint32              `json:"rtp_timestamp"`      // 32 bit
	Pkt_count         uint32              `json:"packets"`            // 32 bit
	Octet_count       uint32              `json:"octets"`             // 32 bit
	ReportBlocks      []RTCP_report_block `json:"report_blocks"`
}

type RTCP_RR struct {
	ReportBlocks []RTCP_report_block `json:"report_blocks"`
}

type RTCP_SDES struct {
}

type RTCP_BYE struct {
}

type RTCP_APP struct {
}

type RTCP_Packet struct {
	Header             RTCP_header `json:"header"`
	Sender_information interface{} `json:"sender_information"`
}

//read data by bit
type BitReader struct {
	buf    []byte
	curBit int
}

func (br *BitReader) Init(data []byte) {
	br.curBit = 0
	br.buf = make([]byte, len(data))
	copy(br.buf, data)
}

func (br *BitReader) ReadBit() int {
	if br.curBit > (len(br.buf) << 3) {
		return -1
	}
	idx := (br.curBit >> 3)
	offset := br.curBit%8 + 1
	br.curBit++
	return int(br.buf[idx]>>uint(8-offset)) & 0x01
}

func (br *BitReader) ReadBits(num int) int {
	r := 0
	for i := 0; i < num; i++ {
		r |= (br.ReadBit() << uint(num-i-1))
	}
	return r
}

func (br *BitReader) Read32Bits() uint32 {
	idx := (br.curBit >> 3)
	var r uint32
	binary.Read(bytes.NewReader(br.buf[idx:]), binary.BigEndian, &r)
	br.curBit += 32
	return r
}

func ParseRTCP(data []byte) ([]byte, error) {
	pkt := &RTCP_Packet{}
	if len(data) < 4 {
		return nil, errors.New("Not enough packets inside RTCP header")
	}

	pkt.Header.Version = (data[0] & 0xc0) >> 6
	pkt.Header.Padding = (data[0] & 0x20) >> 5
	pkt.Header.ReceptionReportCount = data[0] & 0x1f
	pkt.Header.PacketType = data[1]
	pkt.Header.Length = binary.BigEndian.Uint16(data[2:])

	if pkt.Header.ReceptionReportCount < 0 {
		return nil, errors.New("Negative reception report count")
	}
	reader := &BitReader{}
	reader.Init(data[4:])
	switch pkt.Header.PacketType {
	case TYPE_RTCP_SR:
		sr := &RTCP_SR{}
		pkt.Sender_information = sr
		sr.Ssrc = uint32(reader.Read32Bits())
		sr.Ntp_timestamp_MSW = uint32(reader.Read32Bits())
		sr.Ntp_timestamp_LSW = uint32(reader.Read32Bits())
		sr.Rtp_timestamp = uint32(reader.Read32Bits())
		sr.Pkt_count = uint32(reader.Read32Bits())
		sr.Octet_count = uint32(reader.Read32Bits())

		if pkt.Header.ReceptionReportCount > 0 {
			sr.ReportBlocks = make([]RTCP_report_block, pkt.Header.ReceptionReportCount)
			for i := 0; i < int(pkt.Header.ReceptionReportCount); i++ {
				sr.ReportBlocks[i].Ssrc = uint32(reader.Read32Bits())
				sr.ReportBlocks[i].Fraction_lost = byte(reader.ReadBits(8))
				sr.ReportBlocks[i].Cumulative_lost = uint32(reader.ReadBits(24))
				sr.ReportBlocks[i].Highest_seq_no = uint32(reader.Read32Bits())
				sr.ReportBlocks[i].Jitter = uint32(reader.Read32Bits())
				sr.ReportBlocks[i].LastSR = uint32(reader.Read32Bits())
				sr.ReportBlocks[i].Delay_last_SR = uint32(reader.Read32Bits())
			}
		}

	case TYPE_RTCP_RR:
		rr := &RTCP_RR{}
		if pkt.Header.ReceptionReportCount > 0 {
			rr.ReportBlocks = make([]RTCP_report_block, pkt.Header.ReceptionReportCount)
			for i := 0; i < int(pkt.Header.ReceptionReportCount); i++ {
				rr.ReportBlocks[i].Ssrc = uint32(reader.Read32Bits())
				rr.ReportBlocks[i].Fraction_lost = byte(reader.ReadBits(8))
				rr.ReportBlocks[i].Cumulative_lost = uint32(reader.ReadBits(24))
				rr.ReportBlocks[i].Highest_seq_no = uint32(reader.Read32Bits())
				rr.ReportBlocks[i].Jitter = uint32(reader.Read32Bits())
				rr.ReportBlocks[i].LastSR = uint32(reader.Read32Bits())
				rr.ReportBlocks[i].Delay_last_SR = uint32(reader.Read32Bits())
			}
		}
	case TYPE_RTCP_SDES:
		logp.Info("Discard RTCP_SDES packet type: %d", pkt.Header.PacketType)
	case TYPE_RTCP_APP:
		logp.Info("Discard RTCP_APP packet type: %d", pkt.Header.PacketType)
	case TYPE_RTCP_BYE:
		logp.Info("Discard RTCP_BYE packet type: %d", pkt.Header.PacketType)
	default:
		logp.Info("Discard unsupported packet type: %d", pkt.Header.PacketType)
	}
	rtcpPkt, err := json.Marshal(pkt)

	if err != nil {
		fmt.Println("json error!")
		logp.Err("RTCP marshal", err)
		return nil, err
	}

	fmt.Println(string(rtcpPkt))
	return nil, nil
}
