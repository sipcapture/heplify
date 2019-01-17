package publish

import (
	"sync/atomic"
	"time"

	"github.com/sipcapture/heplify/decoder"
	"github.com/negbie/logp"
)

type Outputer interface {
	Output(msg []byte)
}

type Publisher struct {
	pubCount uint64
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
	for pkt := range pq {
		atomic.AddUint64(&pub.pubCount, 1)
		msg := EncodeHEP(pkt)
		pub.output(msg)
	}
}

func (pub *Publisher) printStats() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			logp.Info("Packets since last minute sent: %d", atomic.LoadUint64(&pub.pubCount))
			atomic.StoreUint64(&pub.pubCount, 0)
		}()
	}
}
