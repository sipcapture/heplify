package decoder

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/negbie/fluxify/logp"
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

func (d *Decoder) fragFlush() {
	for {
		<-time.After(1 * time.Minute)
		go d.flush(time.Now())
	}
}

func (d *Decoder) flush(t time.Time) {
	c := d.defragger.DiscardOlderThan(t.Add(-1 * time.Minute))
	logp.Info("Fragment flush counter: %d", c)
}
