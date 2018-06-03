package publish

import (
	"time"

	"github.com/negbie/heplify/decoder"
	"github.com/negbie/logp"
)

type Outputer interface {
	Output(msg []byte)
}

type Publisher struct {
	pktQueue chan *decoder.Packet
	pubCount int
	outputer Outputer
}

func NewPublisher(out Outputer) *Publisher {

	p := &Publisher{
		outputer: out,
		pktQueue: make(chan *decoder.Packet, 20000),
		pubCount: 0,
	}
	go p.Start()
	go p.printStats()
	return p
}

func (pub *Publisher) PublishEvent(pkt *decoder.Packet) {
	pub.pktQueue <- pkt
}

func (pub *Publisher) output(msg []byte) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover %v", err)
		}
	}()
	pub.outputer.Output(msg)
}

func (pub *Publisher) Start() {
	for {
		select {
		case pkt := <-pub.pktQueue:
			pub.pubCount++
			msg := EncodeHEP(pkt)
			pub.output(msg)
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
