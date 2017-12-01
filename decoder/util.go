package decoder

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"time"

	"github.com/negbie/heplify/logp"
)

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

func fastHash(s []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func (d *Decoder) flushFragments() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			d.defragger.DiscardOlderThan(time.Now().Add(-1 * time.Minute))
		}()
	}
}

func (p *Packet) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Host          string
		HEPType       byte
		Tsec          uint32
		Tmsec         uint32
		Vlan          uint16
		Version       uint8
		Protocol      uint8
		SrcIP         net.IP
		DstIP         net.IP
		SrcPort       uint16
		DstPort       uint16
		CorrelationID string
		Payload       string
	}{
		Host:          p.Host,
		HEPType:       p.HEPType,
		Tsec:          p.Tsec,
		Tmsec:         p.Tmsec,
		Vlan:          p.Vlan,
		Version:       p.Version,
		Protocol:      p.Protocol,
		SrcIP:         int2ip(p.SrcIP),
		DstIP:         int2ip(p.DstIP),
		SrcPort:       p.SrcPort,
		DstPort:       p.DstPort,
		CorrelationID: string(p.CorrelationID),
		Payload:       string(p.Payload),
	})
}

func (d *Decoder) printPacketStats() {
	logp.Info("Packets since last minute IPv4: %d, UDP: %d, RTCP: %d, RTCPFail: %d, TCP: %d, DNS: %d, duplicate: %d, fragments: %d, unknown: %d",
		d.ip4Count, d.udpCount, d.rtcpCount, d.rtcpFailCount, d.tcpCount, d.dnsCount, d.dupCount, d.fragCount, d.unknownCount)
	d.ip4Count, d.udpCount, d.rtcpCount, d.rtcpFailCount, d.tcpCount, d.dnsCount, d.dupCount, d.fragCount, d.unknownCount = 0, 0, 0, 0, 0, 0, 0, 0, 0
}

func (d *Decoder) printSIPCacheStats() {
	logp.Info("SIPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.SIPCache.EntryCount(), d.SIPCache.LookupCount(), d.SIPCache.HitCount(), d.SIPCache.ExpiredCount(), d.SIPCache.OverwriteCount())
	d.SIPCache.ResetStatistics()
}

func (d *Decoder) printSDPCacheStats() {
	logp.Info("SDPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.SDPCache.EntryCount(), d.SDPCache.LookupCount(), d.SDPCache.HitCount(), d.SDPCache.ExpiredCount(), d.SDPCache.OverwriteCount())
	d.SDPCache.ResetStatistics()
}

func (d *Decoder) printRTCPCacheStats() {
	logp.Info("RTCPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.RTCPCache.EntryCount(), d.RTCPCache.LookupCount(), d.RTCPCache.HitCount(), d.RTCPCache.ExpiredCount(), d.RTCPCache.OverwriteCount())
	d.RTCPCache.ResetStatistics()
}

func (d *Decoder) printStats() {
	for {
		<-time.After(60 * time.Second)
		go func() {
			d.printPacketStats()
			d.printSIPCacheStats()
			d.printSDPCacheStats()
			d.printRTCPCacheStats()
		}()
	}
}
