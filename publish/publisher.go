package publish

import (
	"sync/atomic"
	"time"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/decoder"
)

var scriptEnable bool

type Outputer interface {
	Output(msg []byte)
	SendPingPacket(msg []byte)
}

type Publisher struct {
	pubCount uint64
	outputer Outputer
	script   decoder.ScriptEngine
}

func NewPublisher(out Outputer) *Publisher {
	p := &Publisher{
		outputer: out,
		pubCount: 0,
	}

	if config.Cfg.ScriptFile != "" {
		var err error
		p.script, err = decoder.NewScriptEngine()
		if err != nil {
			logp.Err("%v, please fix and run killall -HUP heplify", err)
		} else {
			scriptEnable = true
			//defer p.script.Close()
		}
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
		var err error

		//Version == 100 just for forwarding...
		if pkt.Version == 100 {

			if config.Cfg.ReplaceToken {
				tmpver, err := DecodeHEP(pkt.Payload)
				if err == nil {
					tmpver.NodePW = config.Cfg.HepNodePW
					forwardMsg, err := tmpver.Marshal()
					if err == nil {
						pub.output(forwardMsg)
					} else {
						logp.Warn("Bad HEP marshal: %v", err)
					}
				} else {
					logp.Warn("Bad HEP: %v", err)
				}
				continue
			}

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
		} else if pkt.Version == 255 {
			//this is EXIT
			logp.Info("received exit signal")
			if config.Cfg.Iface.EOFExit {
				logp.Info("exiting...")
				config.WgExitGroup.Done()
				return
			}
			break
		} else {

			if scriptEnable {
				for _, v := range config.Cfg.ScriptHEPFilter {
					if int(pkt.ProtoType) == v {
						if err = pub.script.Run(pkt); err != nil {
							logp.Err("%v", err)
						}
						break
					}
				}

				if pkt == nil || pkt.ProtoType == 1 && pkt.Payload == nil {
					logp.Warn("nil struct after script processing")
					continue
				}
			}

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
