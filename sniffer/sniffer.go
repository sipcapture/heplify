package sniffer

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/dump"
	"github.com/sipcapture/heplify/publish"
	"github.com/negbie/logp"
)

type SnifferSetup struct {
	pcapHandle     *pcap.Handle
	afpacketHandle *afpacketHandle
	config         *config.InterfacesConfig
	isAlive        bool
	dumpChan       chan *dump.Packet
	mode           string
	bpf            string
	file           string
	filter         []string
	discard        []string
	worker         Worker
	DataSource     gopacket.PacketDataSource
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

	if config.Cfg.HepServer != "" {
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
	mw.decoder.Process(data, ci)
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
		sniffer.bpf = "tcp and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44)"
	case "SIPDNS":
		sniffer.bpf = "tcp and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 32 and ip and dst port 53)"
	case "SIPLOG":
		sniffer.bpf = "tcp and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 128 and (dst port 514 or port 2223))"
	case "SIPRTP":
		sniffer.bpf = "tcp and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80)"
	default:
		sniffer.mode = "SIPRTCP"
		sniffer.bpf = "tcp and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc)"
	}

	if sniffer.config.WithErspan {
		sniffer.bpf = fmt.Sprintf("%s or proto 47", sniffer.bpf)
	}
	if sniffer.config.WithVlan {
		sniffer.bpf = fmt.Sprintf("%s or (vlan and (%s))", sniffer.bpf, sniffer.bpf)
	}

	if config.Cfg.Filter != "" {
		sniffer.filter = strings.Split(config.Cfg.Filter, ",")
	}
	if config.Cfg.Discard != "" {
		sniffer.discard = strings.Split(config.Cfg.Discard, ",")
	}

	logp.Info("%#v", config.Cfg)
	logp.Info("%#v", config.Cfg.Iface)
	logp.Info("bpf: %s", sniffer.bpf)
	if len(sniffer.discard) > 0 {
		logp.Info("discard: %#v", sniffer.discard)
	}
	if len(sniffer.filter) > 0 {
		logp.Info("filter: %#v", sniffer.filter)
	}
	logp.Info("ostype: %s, osarch: %s", runtime.GOOS, runtime.GOARCH)

	switch sniffer.config.Type {
	case "pcap":
		if sniffer.file != "" {
			if strings.HasSuffix(strings.ToLower(sniffer.file), ".gz") {
				if sniffer.file, err = ungzip(sniffer.file); err != nil {
					return err
				}
			}
			sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.file)
			if err != nil {
				return fmt.Errorf("couldn't open file %v! %v", sniffer.file, err)
			}
			err = sniffer.pcapHandle.SetBPFFilter(sniffer.bpf)
			if err != nil {
				return fmt.Errorf("SetBPFFilter '%s' for ReadFile pcap: %v", sniffer.bpf, err)
			}
		} else {
			sniffer.pcapHandle, err = pcap.OpenLive(sniffer.config.Device, int32(sniffer.config.Snaplen), true, 1*time.Second)
			if err != nil {
				return fmt.Errorf("setting pcap live mode: %v", err)
			}
			err = sniffer.pcapHandle.SetBPFFilter(sniffer.bpf)
			if err != nil {
				return fmt.Errorf("SetBPFFilter '%s' for pcap: %v", sniffer.bpf, err)
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

		sniffer.afpacketHandle, err = newAfpacketHandle(sniffer.config.Device, szFrame, szBlock, numBlocks, 1*time.Second, sniffer.config.WithVlan)
		if err != nil {
			return fmt.Errorf("setting af_packet handle: %v", err)
		}

		err = sniffer.afpacketHandle.SetBPFFilter(sniffer.bpf, sniffer.config.Snaplen)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for af_packet: %v", sniffer.bpf, err)
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
	sniffer.file = sniffer.config.ReadFile

	if sniffer.file == "" {
		if sniffer.config.Device == "any" && runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			_, err := ListDeviceNames(true, false)
			return nil, fmt.Errorf("%v -i any is not supported on %s\nPlease use one of the above devices", err, runtime.GOOS)
		}
	}

	if sniffer.config.Device == "" && sniffer.file == "" {
		_, err := ListDeviceNames(true, false)
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
		sniffer.dumpChan = make(chan *dump.Packet, 20000)
		go dump.Save(sniffer.dumpChan, sniffer.Datalink())
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

LOOP:
	for sniffer.isAlive {
		if sniffer.config.OneAtATime {
			fmt.Println("Press enter to read next packet")
			fmt.Scanln()
		}

		data, ci, err := sniffer.DataSource.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired || sniffer.afpacketHandle.IsErrTimeout(err) || err == syscall.EINTR {
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
				retError = fmt.Errorf("error reopening file: %s", err)
				sniffer.isAlive = false
				continue
			}
			lastPktTime = nil
			continue
		}

		if err != nil {
			retError = fmt.Errorf("sniffing error: %s", err)
			sniffer.isAlive = false
			continue
		}

		if len(data) == 0 {
			continue
		}

		if len(sniffer.filter) > 0 {
			for i := range sniffer.filter {
				if !bytes.Contains(data, []byte(sniffer.filter[i])) {
					continue LOOP
				}
			}
		}
		if len(sniffer.discard) > 0 {
			for i := range sniffer.discard {
				if bytes.Contains(data, []byte(sniffer.discard[i])) {
					continue LOOP
				}
			}
		}

		if sniffer.file != "" {
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
			sniffer.dumpChan <- &dump.Packet{Ci: ci, Data: data}
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

	if sniffer.config.Type != "pcap" || sniffer.file == "" {
		return fmt.Errorf("Reopen is only possible for files and in pcap mode")
	}

	sniffer.Close()
	sniffer.pcapHandle, err = pcap.OpenOffline(sniffer.file)
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
	if sniffer.file != "" {
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
				pcapStats, err := sniffer.pcapHandle.Stats()
				if err != nil {
					logp.Warn("Stats err: %v", err)
				}
				logp.Info("Stats {received dropped-os dropped-int}: {%d %d %d}",
					pcapStats.PacketsReceived, pcapStats.PacketsDropped, pcapStats.PacketsIfDropped)

			case "af_packet":
				p, d, err := sniffer.afpacketHandle.Stats()
				if err != nil {
					logp.Warn("Stats err: %v", err)
				}
				logp.Info("Stats {received dropped}: {%d %d}", p, d)
			}

		case <-signals:
			logp.Info("Sniffer received stop signal")
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
	}
}

func ungzip(inputFile string) (string, error) {
	r, err := os.Open(inputFile)
	if err != nil {
		return "", err
	}
	defer r.Close()

	outputFile, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	defer outputFile.Close()

	pathName := filepath.Join(filepath.Dir(inputFile), outputFile.Name)
	w, err := os.Create(pathName)
	if err != nil {
		return "", err
	}
	defer w.Close()

	_, err = io.Copy(w, outputFile)
	return pathName, err
}
