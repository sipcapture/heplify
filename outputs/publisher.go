package outputs

import (
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
)

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
	if config.Cfg.DoHep {
		pub.hepQueue <- pkt
	}
}

func (pub *Publisher) output(pkt *decoder.Packet) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("pub.output() %v", err)
		}
	}()

	//b, err := json.Marshal(pkt)
	b := toHep(pkt.Hep)
	/* 	if err != nil {
		logp.Err("json.Marshal() %v", err)
		return
	} */
	pub.outputer.Output(b)
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
