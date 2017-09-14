package sniffer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/outputs"
)

type SnifferSetup struct {
	pcapHandle     *pcap.Handle
	afpacketHandle *afpacketHandle
	config         *config.InterfacesConfig
	isAlive        bool
	dumper         *pcapgo.Writer

	// bpf filter
	mode   string
	filter string

	// Decoder    *decoder.DecoderStruct
	worker     Worker
	DataSource gopacket.PacketDataSource
}

type MainWorker struct {
	publisher *outputs.Publisher
	decoder   *decoder.Decoder
}

type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
}

type WorkerFactory func(layers.LinkType) (Worker, error)

func NewWorker(dl layers.LinkType) (Worker, error) {
	var o outputs.Outputer
	var err error

	if config.Cfg.HepServer != "" {
		o, err = outputs.NewHepOutputer(config.Cfg.HepServer)
	} else {
		o, err = outputs.NewFileOutputer()
	}
	if err != nil {
		logp.Critical("NewWorker %v", err)
		panic(err)
	}

	p := outputs.NewPublisher(o)
	d := decoder.NewDecoder()
	w := &MainWorker{publisher: p, decoder: d}
	return w, nil
}

func (mw *MainWorker) OnPacket(data []byte, ci *gopacket.CaptureInfo) {
	pkt, err := mw.decoder.Process(data, ci)
	// TODO check this
	if err != nil {
		logp.Critical("OnPacket %v", err)
		panic(err)
	}
	if pkt != nil {
		mw.publisher.PublishEvent(pkt)
	} else {
		logp.Info("Skip %d bytes packet. Probably fragmented.", ci.Length)
	}
}

func (sniffer *SnifferSetup) setFromConfig(cfg *config.InterfacesConfig) error {
	sniffer.config = cfg

	devices, err := ListDeviceNames(false, false)
	if err != nil {
		return fmt.Errorf("getting devices list: %v", err)
	}
	if sniffer.config.Device == "" {
		fmt.Printf("\nPlease use one of the following devices:\n\n")
		for _, d := range devices {
			if strings.HasPrefix(d, "any") || strings.HasPrefix(d, "bluetooth") || strings.HasPrefix(d, "dbus") || strings.HasPrefix(d, "nf") || strings.HasPrefix(d, "usb") {
				continue
			}
			fmt.Printf("-i %s\n", d)
		}
		fmt.Println("")
		os.Exit(1)
	}

	if sniffer.config.Snaplen == 0 {
		sniffer.config.Snaplen = 65535
	}

	if sniffer.config.Type == "autodetect" || sniffer.config.Type == "" {
		sniffer.config.Type = "pcap"
	}

	if sniffer.mode == "SIP" {
		sniffer.filter = "(greater 300 and portrange 5060-5090 or ip[6:2] & 0x1fff != 0) or (vlan and (greater 300 and portrange 5060-5090 or ip[6:2] & 0x1fff != 0))"
	} else if sniffer.mode == "LOG" {
		sniffer.filter = "greater 100 and port 514"
	} else if sniffer.mode == "DNS" {
		sniffer.filter = "greater 50 and ip and dst port 53"
	} else if sniffer.mode == "TLS" {
		sniffer.filter = "greater 100 and tcp and port 443"
	} else {
		sniffer.mode = "SIP"
		sniffer.filter = "(greater 300 and portrange 5060-5090 or ip[6:2] & 0x1fff != 0) or (vlan and (greater 300 and portrange 5060-5090 or ip[6:2] & 0x1fff != 0))"
	}

	logp.Debug("sniffer", "Sniffer type: %s device: %s mode: %s", sniffer.config.Type, sniffer.config.Device, sniffer.mode)

	switch sniffer.config.Type {
	case "file":
		sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.config.ReadFile)
		if err != nil {
			return fmt.Errorf("couldn't open file %v %v", sniffer.config.ReadFile, err)
		}
		err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for pcap: %v", sniffer.filter, err)
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)

	case "pcap":
		sniffer.pcapHandle, err = pcap.OpenLive(sniffer.config.Device, int32(sniffer.config.Snaplen), true, 500*time.Millisecond)
		if err != nil {
			return fmt.Errorf("setting pcap live mode: %v", err)
		}
		err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for pcap: %v", sniffer.filter, err)
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)

	case "af_packet":
		if sniffer.config.BufferSizeMb == 0 {
			sniffer.config.BufferSizeMb = 32
		}

		szFrame, szBlock, numBlocks, err := afpacketComputeSize(sniffer.config.BufferSizeMb, sniffer.config.Snaplen, os.Getpagesize())
		if err != nil {
			return fmt.Errorf("setting af_packet computesize: %v", err)
		}

		sniffer.afpacketHandle, err = newAfpacketHandle(sniffer.config.Device, szFrame, szBlock, numBlocks, 500*time.Millisecond)
		if err != nil {
			return fmt.Errorf("setting af_packet handle: %v", err)
		}

		err = sniffer.afpacketHandle.SetBPFFilter(sniffer.filter)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for af_packet: %v", sniffer.filter, err)
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.afpacketHandle)

	default:
		return fmt.Errorf("unknown sniffer type: %s", sniffer.config.Type)
	}

	return nil
}

func (sniffer *SnifferSetup) Reopen() error {
	var err error

	if sniffer.config.Type != "file" || sniffer.config.ReadFile == "" {
		return fmt.Errorf("Reopen is only possible for files")
	}

	sniffer.pcapHandle.Close()
	sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.config.ReadFile)
	if err != nil {
		return err
	}

	sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)

	return nil
}

func (sniffer *SnifferSetup) Datalink() layers.LinkType {
	if sniffer.config.Type == "pcap" {
		return sniffer.pcapHandle.LinkType()
	}
	return layers.LinkTypeEthernet
}

func (sniffer *SnifferSetup) Init(testMode bool, mode string, factory WorkerFactory, interfaces *config.InterfacesConfig) error {
	var err error
	sniffer.mode = mode

	if !testMode {
		err = sniffer.setFromConfig(interfaces)
		if err != nil {
			return err
		}
	}

	if interfaces.ReadFile == "" {
		if interfaces.Device == "any" {
			// OS X or Windows
			if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
				return fmt.Errorf("any interface is not supported on %s", runtime.GOOS)
			}
		}
	}

	sniffer.worker, err = factory(sniffer.Datalink())
	if err != nil {
		return fmt.Errorf("creating decoder: %v", err)
	}

	if sniffer.config.WriteFile != "" {
		f, err := os.Create(sniffer.config.WriteFile)
		if err != nil {
			return fmt.Errorf("creating pcap: %v", err)
		}
		w := pcapgo.NewWriter(f)
		err = w.WriteFileHeader(uint32(sniffer.config.Snaplen), sniffer.Datalink())
		if err != nil {
			return fmt.Errorf("pcap writer: %v", err)
		}

		sniffer.dumper = w
	}

	sniffer.isAlive = true

	return nil
}

func (sniffer *SnifferSetup) Run() error {
	counter := 0
	loopCount := 1
	var lastPktTime *time.Time
	var retError error

	for sniffer.isAlive {
		if sniffer.config.OneAtATime {
			fmt.Println("Press enter to read packet")
			fmt.Scanln()
		}

		data, ci, err := sniffer.DataSource.ReadPacketData()

		if config.Cfg.Filter != "" && bytes.Contains(data, []byte(config.Cfg.Filter)) {
			continue
		}

		if err == pcap.NextErrorTimeoutExpired || err == syscall.EINTR {
			logp.Debug("sniffer", "Idle")
			continue
		}

		if err == io.EOF {
			logp.Debug("sniffer", "End of file")
			loopCount++
			if sniffer.config.Loop > 0 && loopCount > sniffer.config.Loop {
				// time for the publish goroutine to flush
				time.Sleep(300 * time.Millisecond)
				sniffer.isAlive = false
				continue
			}

			logp.Debug("sniffer", "Reopening the file")
			err = sniffer.Reopen()
			if err != nil {
				retError = fmt.Errorf("Error reopening file: %s", err)
				sniffer.isAlive = false
				continue
			}
			lastPktTime = nil
			continue
		}

		if err != nil {
			retError = fmt.Errorf("Sniffing error: %s", err)
			sniffer.isAlive = false
			continue
		}

		if len(data) == 0 {
			// Empty packet, probably timeout from afpacket
			logp.Debug("sniffer", "Empty data packet")
			continue
		}

		if sniffer.config.ReadFile != "" {
			if lastPktTime != nil && !sniffer.config.TopSpeed {
				sleep := ci.Timestamp.Sub(*lastPktTime)
				if sleep > 0 {
					time.Sleep(sleep)
				} else {
					logp.Warn("Time in pcap went backwards: %d", sleep)
				}
			}
			_lastPktTime := ci.Timestamp
			lastPktTime = &_lastPktTime
			if !sniffer.config.TopSpeed {
				// Overwrite what we get from the pcap
				ci.Timestamp = time.Now()
			}
		} else if sniffer.config.WriteFile != "" {
			err := sniffer.dumper.WritePacket(ci, data)
			if err != nil {
				return fmt.Errorf("couldn't write to file %v %v", sniffer.config.WriteFile, err)
			}
		}

		counter++
		if counter%1024 == 0 {
			logp.Info("Receive packet counter: %d", counter)
		}

		sniffer.worker.OnPacket(data, &ci)
	}

	logp.Info("Input finish. Processed %d packets. Have a nice day!", counter)
	sniffer.pcapHandle.Close()

	return retError
}

func (sniffer *SnifferSetup) Close() error {
	switch sniffer.config.Type {
	case "pcap":
		sniffer.pcapHandle.Close()
	case "af_packet":
		sniffer.afpacketHandle.Close()
	}
	return nil
}

func (sniffer *SnifferSetup) Stop() error {
	sniffer.isAlive = false
	return nil
}

func (sniffer *SnifferSetup) IsAlive() bool {
	return sniffer.isAlive
}
