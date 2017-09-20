package decoder

import (
	"encoding/binary"
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

func (d *Decoder) flushFrag() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			d.defragger.DiscardOlderThan(time.Now().Add(-1 * time.Minute))
		}()
	}
}

func (d *Decoder) printStats() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			logp.Info("Packets since last minute IPv4: %d, UDP: %d, TCP: %d, DNS: %d, duplicate: %d, fragments: %d, unknown: %d",
				d.ip4Count, d.udpCount, d.tcpCount, d.dnsCount, d.dupCount, d.fragCount, d.unknownCount)
			d.fragCount, d.dupCount, d.ip4Count, d.udpCount, d.tcpCount, d.dnsCount, d.unknownCount = 0, 0, 0, 0, 0, 0, 0
		}()
	}
}
