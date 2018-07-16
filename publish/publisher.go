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
	pubCount int
	outputer Outputer
}

func NewPublisher(out Outputer) *Publisher {
	p := &Publisher{
		outputer: out,
		pubCount: 0,
	}
	go p.Start(decoder.PacketQueue)
	go p.printStats()
	return p
}

func (pub *Publisher) output(msg []byte) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover %v", err)
		}
	}()
	pub.outputer.Output(msg)
}

func (pub *Publisher) Start(pq chan *decoder.Packet) {
	for {
		select {
		case pkt := <-pq:
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
