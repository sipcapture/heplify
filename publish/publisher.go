package publish

import (
	"sync/atomic"
	"time"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/decoder"
)

type Outputer interface {
	Output(msg []byte)
	SendPingPacket(msg []byte)
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

func (pub *Publisher) setHEPPing(msg []byte) {
	defer func() {
		if err := recover(); err != nil {
			logp.Err("recover setHEPPing %v", err)
		}
	}()
	pub.outputer.SendPingPacket(msg)
}

func (pub *Publisher) Start(pq chan *decoder.Packet) {
	for pkt := range pq {

		atomic.AddUint64(&pub.pubCount, 1)

		//Version == 100 just for forwarding...
		if pkt.Version == 100 {
			pub.output(pkt.Payload)
			logp.Debug("publisher", "sent hep message from collector")
		} else if pkt.Version == 0 {
			//this is PING
			msg, err := EncodeHEP(pkt)
			if err != nil {
				logp.Warn("%v", err)
				continue
			}
			pub.setHEPPing(msg)
			logp.Debug("publisher", "sent hep ping from collector")
		} else {
			msg, err := EncodeHEP(pkt)
			if err != nil {
				logp.Warn("%v", err)
				continue
			}

			pub.output(msg)
		}
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
