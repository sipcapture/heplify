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

func (d *Decoder) fragFlush() {
	for {
		<-time.After(1 * time.Minute)
		go d.flush()
	}
}

func (d *Decoder) flush() {
	c := d.defragger.DiscardOlderThan(time.Now().Add(-1 * time.Minute))
	logp.Info("Fragment flush counter: %d", c)
}
