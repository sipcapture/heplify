package outputs

import (
	"encoding/json"
	"hash"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"

	"github.com/cespare/xxhash"
	lru "github.com/hashicorp/golang-lru"
)

type Outputer interface {
	Output(msg []byte)
}

type Publisher struct {
	hepQueue chan *decoder.Packet
	outputer Outputer
	hepDedup *lru.ARCCache
	hash     hash.Hash64
}

func NewPublisher(o Outputer) *Publisher {
	l, err := lru.NewARC(8192)
	h := xxhash.New()
	if err != nil {
		logp.Err("lru %v", err)
	}
	p := &Publisher{
		hepQueue: make(chan *decoder.Packet),
		outputer: o,
		hepDedup: l,
		hash:     h,
	}
	go p.Start()
	return p
}

func (pub *Publisher) PublishEvent(pkt *decoder.Packet) {
	pub.hepQueue <- pkt
}

func (pub *Publisher) output(pkt *decoder.Packet) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover %v", err)
		}
	}()

	if config.Cfg.HepDedup && config.Cfg.HepServer != "" {
		pub.hash.Write(pkt.Payload)
		key := pub.hash.Sum64()
		_, dup := pub.hepDedup.Get(key)
		if dup == false {
			hepPacket := convertToHep(pkt)
			pub.outputer.Output(hepPacket)
			pub.hepDedup.Add(key, nil)
		} else {
			logp.Debug("publisher", "Got duplicate packet with hash: %v\n", key)
		}
		pub.hash.Reset()

	} else if config.Cfg.HepServer != "" {
		hepPacket := convertToHep(pkt)
		pub.outputer.Output(hepPacket)
	} else {
		jsonPacket, err := json.MarshalIndent(pkt, "", "  ")
		if err != nil {
			logp.Err("json %v", err)
			return
		}
		pub.outputer.Output(jsonPacket)
	}
}

func (pub *Publisher) Start() {
	counter := 0
	for {
		select {
		case pkt := <-pub.hepQueue:
			counter++
			pub.output(pkt)
		}

		if counter%1024 == 0 {
			logp.Debug("publisher", "Sent packet counter: %d", counter)
		}
	}
}
