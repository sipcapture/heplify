package publish

import (
	"encoding/json"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

type Outputer interface {
	Output(msg []byte)
}

type Publisher struct {
	hepQueue chan *decoder.Packet
	outputer Outputer
}

func NewPublisher(o Outputer) *Publisher {

	p := &Publisher{
		hepQueue: make(chan *decoder.Packet),
		outputer: o,
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

	if config.Cfg.HepServer != "" {
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
			logp.Info("Sent packet counter: %d", counter)
		}
	}
}
