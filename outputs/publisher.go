package outputs

import (
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
	lru, err := lru.NewARC(1024)
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
	if config.Cfg.HepConvert {
		pub.hepQueue <- pkt
	}
}

func (pub *Publisher) output(pkt *decoder.Packet) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("pub.output() %v", err)
		}
	}()

	if config.Cfg.HepDedup {
		_, dup := pub.hepDedup.Get(string(pkt.Hep.Payload))
		if dup == false {
			hepPacket := convertToHep(pkt.Hep)
			pub.outputer.Output(hepPacket)
		}
		pub.hepDedup.Add(string(pkt.Hep.Payload), nil)
	} else {
		//b, err := json.Marshal(pkt)
		hepPacket := convertToHep(pkt.Hep)
		/* 	if err != nil {
			logp.Err("json.Marshal() %v", err)
			return
		} */
		pub.outputer.Output(hepPacket)
	}
}

func (pub *Publisher) Start() {
	counter := 0
	for {
		select {
		case pkt := <-pub.hepQueue:
			pub.output(pkt)
			counter++
		}

		if counter%1024 == 0 {
			logp.Debug("publisher", "Packet number: %d", counter)
		}
	}
}
