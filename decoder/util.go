package decoder

import (
	"container/list"
	"encoding/binary"
	"net"
	"sync"
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

type cacheValue struct {
	key   string
	bytes []byte
}

// Just an estimate
func (v *cacheValue) size() uint64 {
	return uint64(len([]byte(v.key)) + len(v.bytes))
}

type Cache struct {
	sync.Mutex
	Size     uint64
	capacity uint64
	list     *list.List
	table    map[string]*list.Element
}

// NewLRUCache with a maximum size of capacity bytes.
func NewLRUCache(capacity uint64) *Cache {
	return &Cache{
		capacity: capacity,
		list:     list.New(),
		table:    make(map[string]*list.Element),
	}
}

// Set some {key, document} into the cache. Doesn't do anything if the key is already present.
func (c *Cache) Add(key string, document []byte) {
	c.Lock()
	defer c.Unlock()

	_, ok := c.table[key]
	if ok {
		return
	}
	v := &cacheValue{key, document}
	elt := c.list.PushFront(v)
	c.table[key] = elt
	c.Size += v.size()
	for c.Size > c.capacity {
		elt := c.list.Back()
		if elt == nil {
			return
		}
		v := c.list.Remove(elt).(*cacheValue)
		delete(c.table, v.key)
		c.Size -= v.size()
	}
}

// Get retrieves a value from the cache and returns the value and an indicator boolean to show whether it was
// present.
func (c *Cache) Get(key string) (document []byte, ok bool) {
	c.Lock()
	defer c.Unlock()

	elt, ok := c.table[key]
	if !ok {
		return nil, false
	}
	c.list.MoveToFront(elt)
	return elt.Value.(*cacheValue).bytes, true
}
