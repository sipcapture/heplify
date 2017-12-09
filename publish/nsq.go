package publish

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/negbie/heplify/logp"
	"github.com/nsqio/go-nsq"
)

type NSQOutputer struct {
	Addr      string
	Topic     string
	nsqQueue  chan []byte
	producers map[string]*nsq.Producer
}

func NewNSQOutputer(addrs string, topic string) (*NSQOutputer, error) {
	nq := &NSQOutputer{
		Addr:     addrs,
		Topic:    topic,
		nsqQueue: make(chan []byte, 10000),
	}
	err := nq.Init()
	if err != nil {
		return nil, err
	}
	go nq.Start()
	return nq, nil
}

func (nq *NSQOutputer) Close() {
	for _, producer := range nq.producers {
		producer.Stop()
	}
}

func (nq *NSQOutputer) Init() error {
	cfg := nsq.NewConfig()
	cfg.UserAgent = fmt.Sprintf("heplify_nsq-%s", nsq.VERSION)
	cfg.DialTimeout = time.Millisecond * time.Duration(2000)

	nq.producers = make(map[string]*nsq.Producer)
	nsqAddrs := strings.Split(nq.Addr, ",")
	for _, addr := range nsqAddrs {
		producer, err := nsq.NewProducer(addr, cfg)
		if err != nil {
			logp.Err("nsq Init: %v", err)
			return err
		}
		producer.SetLogger(log.New(ioutil.Discard, "", log.LstdFlags), nsq.LogLevelInfo)
		nq.producers[addr] = producer
	}
	return nil
}

func (nq *NSQOutputer) Output(msg []byte) {
	logp.Debug("nsq", "NSQ packet: %s", msg)
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(msg)
	w.Close()
	nq.nsqQueue <- buf.Bytes()
}

func (nq *NSQOutputer) Send(msg []byte) {
	for _, producer := range nq.producers {
		err := producer.Publish(nq.Topic, msg)
		if err != nil {
			logp.Err("nsq Send: %v", err)
			continue
		}
		break
	}
}

func (nq *NSQOutputer) Start() {
	defer nq.Close()
	for {
		select {
		case msg := <-nq.nsqQueue:
			nq.Send(msg)
		}
	}
}
