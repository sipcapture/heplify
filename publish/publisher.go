package publish

import (
	"encoding/json"
	"time"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

type Outputer interface {
	Output(msg []byte)
}

type Publisher struct {
	hepQueue chan *decoder.Packet
	pubCount int
	outputer Outputer
}

func NewPublisher(o Outputer) *Publisher {

	p := &Publisher{
		hepQueue: make(chan *decoder.Packet),
		pubCount: 0,
		outputer: o,
	}
	go p.Start()
	go p.printStats()
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

	if config.Cfg.HepServer != "" {
		hepPacket := NewHEP(pkt)
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
			pub.pubCount++
			pub.output(pkt)
		}
	}
}

func (pub *Publisher) printStats() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			logp.Info("Packets since last minute sent: %d", pub.pubCount)
			pub.pubCount = 0
		}()
	}
}
