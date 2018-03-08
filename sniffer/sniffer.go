package sniffer

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/decoder"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/publish"
)

type SnifferSetup struct {
	pcapHandle     *pcap.Handle
	afpacketHandle *afpacketHandle
	config         *config.InterfacesConfig
	isAlive        bool
	dumpChan       chan DumpPacket
	mode           string
	filter         string
	worker         Worker
	DataSource     gopacket.PacketDataSource
	pcapStats      *pcap.Stats
	afpacketStats  afpacket.Stats
}

type DumpPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

type MainWorker struct {
	publisher *publish.Publisher
	decoder   *decoder.Decoder
}

type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
}

type WorkerFactory func(layers.LinkType) (Worker, error)

func NewWorker(lt layers.LinkType) (Worker, error) {
	var o publish.Outputer
	var err error

	if config.Cfg.HepTLSProxy != "" {
		o, err = publish.NewHEPOutputer(config.Cfg.HepTLSProxy)
	} else if config.Cfg.HepServer != "" {
		o, err = publish.NewHEPOutputer(config.Cfg.HepServer)
	} else {
		o, err = publish.NewFileOutputer()
	}
	if err != nil {
		return nil, err
	}

	p := publish.NewPublisher(o)
	d := decoder.NewDecoder(lt)
	w := &MainWorker{publisher: p, decoder: d}
	return w, nil
}

func (mw *MainWorker) OnPacket(data []byte, ci *gopacket.CaptureInfo) {
	pkt, err := mw.decoder.Process(data, ci)
	if err != nil {
		logp.Critical("OnPacket %v", err)
		panic(err)
	}
	if pkt != nil {
		mw.publisher.PublishEvent(pkt)
	}
}

func (sniffer *SnifferSetup) setFromConfig() error {
	var err error

	if sniffer.config.Snaplen <= 0 {
		sniffer.config.Snaplen = 65535
	}

	if sniffer.config.Type != "af_packet" {
		sniffer.config.Type = "pcap"
	}

	switch sniffer.mode {
	case "SIP":
		sniffer.filter = "(greater 256 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0)"
	case "SIPDNS":
		sniffer.filter = "(greater 256 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 32 and ip and dst port 53)"
	case "SIPLOG":
		sniffer.filter = "(greater 256 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 128 and (dst port 514 or port 2223))"
	case "SIPRTP":
		sniffer.filter = "(greater 256 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80)"
	default:
		sniffer.mode = "SIPRTCP"
		sniffer.filter = "(greater 256 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc)"
	}

	if sniffer.config.WithVlan {
		sniffer.filter = fmt.Sprintf("%s or (vlan and (%s))", sniffer.filter, sniffer.filter)
	}
	if sniffer.config.WithErspan {
		sniffer.filter = fmt.Sprintf("%s or proto 47", sniffer.filter)
	}

	logp.Info("Sniffer [type:%s, device:%s, mode:%s] OS [type:%s, arch:%s]",
		sniffer.config.Type, sniffer.config.Device, sniffer.mode, runtime.GOOS, runtime.GOARCH)

	switch sniffer.config.Type {
	case "pcap":
		if sniffer.config.ReadFile != "" {
			sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.config.ReadFile)
			if err != nil {
				return fmt.Errorf("couldn't open file %v! %v", sniffer.config.ReadFile, err)
			}
			err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
			if err != nil {
				return fmt.Errorf("SetBPFFilter '%s' for ReadFile pcap: %v", sniffer.filter, err)
			}
		} else {
			sniffer.pcapHandle, err = pcap.OpenLive(sniffer.config.Device, int32(sniffer.config.Snaplen), true, pcap.BlockForever)
			if err != nil {
				return fmt.Errorf("setting pcap live mode: %v", err)
			}
			err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
			if err != nil {
				return fmt.Errorf("SetBPFFilter '%s' for pcap: %v", sniffer.filter, err)
			}
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)

	case "af_packet":
		if sniffer.config.BufferSizeMb <= 0 {
			sniffer.config.BufferSizeMb = 32
		}

		szFrame, szBlock, numBlocks, err := afpacketComputeSize(sniffer.config.BufferSizeMb, sniffer.config.Snaplen, os.Getpagesize())
		if err != nil {
			return fmt.Errorf("setting af_packet computesize: %v", err)
		}

		sniffer.afpacketHandle, err = newAfpacketHandle(sniffer.config.Device, szFrame, szBlock, numBlocks, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("setting af_packet handle: %v", err)
		}

		err = sniffer.afpacketHandle.SetBPFFilter(sniffer.filter, sniffer.config.Snaplen)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for af_packet: %v", sniffer.filter, err)
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.afpacketHandle)

	default:
		return fmt.Errorf("unknown sniffer type: %s", sniffer.config.Type)
	}

	return nil
}

func New(mode string, cfg *config.InterfacesConfig) (*SnifferSetup, error) {
	var err error
	sniffer := &SnifferSetup{}
	sniffer.config = cfg
	sniffer.mode = mode

	if sniffer.config.ReadFile == "" {
		if sniffer.config.Device == "any" && runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			_, err := ListDeviceNames(false, false)
			return nil, fmt.Errorf("%v -i any is not supported on %s\nPlease use one of the above devices", err, runtime.GOOS)
		}
	}

	if sniffer.config.Device == "" && sniffer.config.ReadFile == "" {
		_, err := ListDeviceNames(false, false)
		return nil, fmt.Errorf("%v Please use one of the above devices", err)
	}

	err = sniffer.setFromConfig()
	if err != nil {
		return nil, err
	}

	sniffer.worker, err = NewWorker(sniffer.Datalink())
	if err != nil {
		return nil, err
	}

	if sniffer.config.WriteFile != "" {
		sniffer.dumpChan = make(chan DumpPacket, 100000)
		go sniffer.dumpPcap()
	}

	sniffer.isAlive = true
	go sniffer.printStats()

	return sniffer, nil
}

func (sniffer *SnifferSetup) Run() error {
	var (
		loopCount   = 1
		lastPktTime *time.Time
		retError    error
	)

	if config.Cfg.Bench {
		benchmark()
	}

	for sniffer.isAlive {
		if sniffer.config.OneAtATime {
			fmt.Println("Press enter to read next packet")
			fmt.Scanln()
		}

		data, ci, err := sniffer.DataSource.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired || err == syscall.EINTR {
			logp.Debug("sniffer", "Interrupted")
			continue
		}

		if err == io.EOF {
			logp.Debug("sniffer", "End of file")
			loopCount++
			if sniffer.config.Loop > 0 && loopCount > sniffer.config.Loop {
				// Give the publish goroutine 200 ms to flush
				time.Sleep(200 * time.Millisecond)
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
			if lastPktTime != nil && !sniffer.config.ReadSpeed {
				sleep := ci.Timestamp.Sub(*lastPktTime)
				if sleep > 0 {
					time.Sleep(sleep)
				} else {
					logp.Warn("Time in pcap went backwards: %d", sleep)
				}
			}
			_lastPktTime := ci.Timestamp
			lastPktTime = &_lastPktTime
			if !sniffer.config.ReadSpeed {
				// Overwrite what we get from the pcap
				ci.Timestamp = time.Now()
			}
		} else if sniffer.config.WriteFile != "" {
			sniffer.dumpChan <- DumpPacket{ci, data}
		}

		sniffer.worker.OnPacket(data, &ci)
	}
	sniffer.Close()
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

func (sniffer *SnifferSetup) Reopen() error {
	var err error
	time.Sleep(250 * time.Millisecond)

	if sniffer.config.Type != "pcap" || sniffer.config.ReadFile == "" {
		return fmt.Errorf("Reopen is only possible for files and in pcap mode")
	}

	sniffer.Close()
	sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.config.ReadFile)
	if err != nil {
		return err
	}

	sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)

	return nil
}

func (sniffer *SnifferSetup) Stop() error {
	sniffer.isAlive = false
	return nil
}

func (sniffer *SnifferSetup) Datalink() layers.LinkType {
	if sniffer.config.Type == "pcap" {
		return sniffer.pcapHandle.LinkType()
	} else if sniffer.config.Type == "af_packet" {
		return sniffer.afpacketHandle.LinkType()
	}
	return layers.LinkTypeEthernet
}

func (sniffer *SnifferSetup) IsAlive() bool {
	return sniffer.isAlive
}

func (sniffer *SnifferSetup) printStats() {
	var err error
	if sniffer.config.ReadFile != "" {
		logp.Info("Read in pcap file. Stats won't be generated.")
		return
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-ticker.C:
			switch sniffer.config.Type {
			case "pcap":
				sniffer.pcapStats, err = sniffer.pcapHandle.Stats()
				if err != nil {
					logp.Warn("Stats err: %v", err)
				}
				logp.Info("Packets overall received: %d, dropped by OS: %d, dropped by interface: %d",
					sniffer.pcapStats.PacketsReceived, sniffer.pcapStats.PacketsDropped, sniffer.pcapStats.PacketsIfDropped)

			case "af_packet":
				sniffer.afpacketStats, err = sniffer.afpacketHandle.Stats()
				if err != nil {
					logp.Warn("Stats err: %v", err)
				}
				logp.Info("Packets overall received: %d, polls: %d",
					sniffer.afpacketStats.Packets, sniffer.afpacketStats.Polls)
			}

		case <-signals:
			logp.Info("Sniffer received stop signal")
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
	}
}
