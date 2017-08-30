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
	hepDeDup *lru.ARCCache
}

func NewPublisher(o Outputer) *Publisher {
	lrudup, _ := lru.NewARC(10000)
	p := &Publisher{
		hepQueue: make(chan *decoder.Packet),
		outputer: o,
		hepDeDup: lrudup,
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

	_, ok := pub.hepDeDup.Get(string(pkt.Hep.Payload))
	if ok {
		logp.Info("duplicate hep %s", pkt.Hep.Payload)
	} else {
		logp.Info("send hep %s", pkt.Hep.Payload)

		//b, err := json.Marshal(pkt)
		b := toHep(pkt.Hep)
		/* 	if err != nil {
			logp.Err("json.Marshal() %v", err)
			return
		} */
		pub.outputer.Output(b)
	}
	pub.hepDeDup.Add(string(pkt.Hep.Payload), nil)
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
