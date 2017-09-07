package outputs

import (
	"encoding/json"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"

	lru "github.com/hashicorp/golang-lru"
)

type Publisher struct {
	hepQueue chan *decoder.Packet
	outputer Outputer
	hepDedup *lru.ARCCache
}

func NewPublisher(o Outputer) *Publisher {
	lru, err := lru.NewARC(8192)
	if err != nil {
		logp.Err("lru %v", err)
	}
	p := &Publisher{
		hepQueue: make(chan *decoder.Packet),
		outputer: o,
		hepDedup: lru,
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
		//md5Key := fmt.Sprintf("%x", md5.Sum(pkt.Payload))
		_, dup := pub.hepDedup.Get(string(pkt.Payload))
		if dup == false {
			hepPacket := convertToHep(pkt)
			pub.outputer.Output(hepPacket)
			pub.hepDedup.Add(string(pkt.Payload), nil)
		}

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
	for {
		select {
		case pkt := <-pub.hepQueue:
			pub.output(pkt)
		}
	}
}
