package sniffer

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/decoder"
	"github.com/sipcapture/heplify/dump"
	"github.com/sipcapture/heplify/publish"
)

type SnifferSetup struct {
	pcapHandle       *pcap.Handle
	afpacketHandle   *afpacketHandle
	config           *config.InterfacesConfig
	isAlive          bool
	dumpChan         chan *dump.Packet
	mode             string
	collectorAddress string
	isCollector      bool
	collectOnlySIP   bool
	bpf              string
	file             string
	filter           []string
	discard          []string
	worker           Worker
	collectorUDPconn *net.UDPConn
	collectorTCPconn *net.TCPListener
	isCollectorTcp   bool
	DataSource       gopacket.PacketDataSource
	stats
}

type MainWorker struct {
	publisher *publish.Publisher
	decoder   *decoder.Decoder
}

type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
	OnHEPPacket(data []byte)
}

type stats struct {
	hepTcpCount  uint64
	hepUDPCount  uint64
	hepSIPCount  uint64
	hepDropCount uint64
	unknownCount uint64
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

func (mw *MainWorker) OnHEPPacket(data []byte) {
	mw.decoder.ProcessHEPPacket(data)
}

func (sniffer *SnifferSetup) setFromConfig() error {
	var err error

	if sniffer.config.Snaplen <= 0 {
		sniffer.config.Snaplen = 65535
	}

	if sniffer.config.Type != "af_packet" {
		sniffer.config.Type = "pcap"
	}

	if sniffer.isCollector {
		sniffer.config.Type = "collector"
	}

	switch sniffer.mode {
	case "SIP":
		sniffer.bpf = "(tcp or sctp) and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44)"
	case "SIPDNS":
		sniffer.bpf = "(tcp or sctp) and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 32 and ip and dst port 53)"
	case "SIPLOG":
		sniffer.bpf = "(tcp or sctp) and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc) or (greater 128 and (dst port 514 or port 2223))"
	case "SIPRTP":
		sniffer.bpf = "(tcp or sctp) and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80)"
	default:
		sniffer.mode = "SIPRTCP"
		sniffer.bpf = "(tcp or sctp) and greater 42 and portrange " + sniffer.config.PortRange + " or (udp and greater 128 and portrange " + sniffer.config.PortRange + " or ip[6:2] & 0x1fff != 0 or ip6[6]=44) or (ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc)"
	}

	if sniffer.config.WithErspan {
		sniffer.bpf = fmt.Sprintf("%s or proto 47", sniffer.bpf)
	}
	if sniffer.config.WithVlan {
		sniffer.bpf = fmt.Sprintf("%s or (vlan and (%s))", sniffer.bpf, sniffer.bpf)
	}
	if sniffer.config.CustomBPF != "" {
		sniffer.bpf = sniffer.config.CustomBPF
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

		if sniffer.config.FanoutID > 0 {
			err = sniffer.afpacketHandle.SetFanout(uint16(sniffer.config.FanoutID))
			if err != nil {
				return fmt.Errorf("SetFanout '%d' for af_packet: %v", uint16(sniffer.config.FanoutID), err)
			}
		}

		err = sniffer.afpacketHandle.SetBPFFilter(sniffer.bpf, sniffer.config.Snaplen)
		if err != nil {
			return fmt.Errorf("SetBPFFilter '%s' for af_packet: %v", sniffer.bpf, err)
		}

		sniffer.DataSource = gopacket.PacketDataSource(sniffer.afpacketHandle)

	case "collector":

		if !strings.HasPrefix(sniffer.collectorAddress, "udp:") && !strings.HasPrefix(sniffer.collectorAddress, "tcp:") {
			return fmt.Errorf("collector support only udp and tcp right now ")
		}

		//host
		hostAdress := sniffer.collectorAddress[4:]

		if strings.HasPrefix(sniffer.collectorAddress, "udp:") {

			laddr, err := net.ResolveUDPAddr("udp", hostAdress)
			if nil != err {
				logp.Err("ResolveTCPAddr error: %v\n", err)
				return err
			}
			sniffer.collectorUDPconn, err = net.ListenUDP("udp", laddr)

			if err != nil {
				defer sniffer.collectorUDPconn.Close()
				return fmt.Errorf("couldn't start collector server: %v", err)
			}

			logp.Info("collector udp server listening %s\n", sniffer.collectorUDPconn.LocalAddr().String())
		} else {

			// listen workers
			laddr, err := net.ResolveTCPAddr("tcp", hostAdress)
			if nil != err {
				logp.Err("ResolveTCPAddr error: %v\n", err)
				return err
			}

			sniffer.collectorTCPconn, err = net.ListenTCP("tcp", laddr)
			if err != nil {
				logp.Err("collectorTCPconn error: %v\n", err)
				return err
			}

			sniffer.isCollectorTcp = true

			if err != nil {
				defer sniffer.collectorUDPconn.Close()
				return fmt.Errorf("couldn't start collector server: %v", err)
			}

			logp.Info("collector tcp server listening %s\n", sniffer.collectorTCPconn.Addr().String())
		}

	default:
		return fmt.Errorf("unknown sniffer type: %s", sniffer.config.Type)
	}

	return nil
}

//mode string, cfg *config.InterfacesConfig, collector string, onlySip bool

func New(cfgMain *config.Config) (*SnifferSetup, error) {
	var err error
	sniffer := &SnifferSetup{}
	sniffer.config = cfgMain.Iface
	sniffer.mode = cfgMain.Mode
	sniffer.file = sniffer.config.ReadFile

	if cfgMain.HepCollector != "" {
		sniffer.collectorAddress = cfgMain.HepCollector
		sniffer.isCollector = true
		sniffer.collectOnlySIP = cfgMain.CollectOnlySip
	}

	if sniffer.file == "" {
		if sniffer.config.Device == "any" && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") {
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

func (sniffer *SnifferSetup) SendPing() error {

	var hepPacket = []byte{0x48, 0x45, 0x50, 0x33, 0x3, 0xa, 0x0, 0x0, 0x0, 0x1, 0x0, 0x7, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x7, 0x11, 0x0, 0x0, 0x0, 0x3, 0x0, 0xa, 0xc0, 0xa8, 0xf7, 0xfa, 0x0, 0x0, 0x0, 0x4, 0x0, 0xa, 0xc0, 0xa8, 0xf5, 0xfa, 0x0, 0x0, 0x0, 0x7, 0x0, 0x8, 0x13, 0xc4, 0x0, 0x0, 0x0, 0x8, 0x0, 0x8, 0x13, 0xc4, 0x0, 0x0, 0x0, 0x9, 0x0, 0xa, 0x5a, 0xa2, 0x9b, 0x98, 0x0, 0x0, 0x0, 0xa, 0x0, 0xa, 0x0, 0x1, 0xd2, 0xf4, 0x0, 0x0, 0x0, 0xb, 0x0, 0x7, 0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe, 0x0, 0x6, 0x0, 0x0, 0x0, 0xf, 0x2, 0xa7, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0xd, 0xa, 0x43, 0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x20, 0x42, 0x43, 0x30, 0x39, 0x39, 0x38, 0x38, 0x34, 0x40, 0x36, 0x64, 0x66, 0x63, 0x66, 0x66, 0x65, 0x38, 0xd, 0xa, 0x43, 0x53, 0x65, 0x71, 0x3a, 0x20, 0x32, 0x31, 0x35, 0x38, 0x33, 0x34, 0x34, 0x38, 0x39, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0xd, 0xa, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x31, 0x31, 0x2e, 0x31, 0x31, 0x31, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3e, 0x3b, 0x74, 0x61, 0x67, 0x3d, 0x36, 0x64, 0x66, 0x63, 0x66, 0x66, 0x65, 0x38, 0x2b, 0x31, 0x2b, 0x62, 0x30, 0x61, 0x39, 0x30, 0x30, 0x30, 0x33, 0x2b, 0x63, 0x39, 0x65, 0x66, 0x63, 0x32, 0x30, 0x62, 0xd, 0xa, 0x54, 0x6f, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x31, 0x31, 0x2e, 0x31, 0x31, 0x31, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3b, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x3d, 0x75, 0x64, 0x70, 0x3e, 0x3b, 0x74, 0x61, 0x67, 0x3d, 0x31, 0x38, 0x30, 0x34, 0x61, 0x34, 0x37, 0x64, 0x2b, 0x31, 0x2b, 0x65, 0x31, 0x30, 0x35, 0x30, 0x34, 0x37, 0x30, 0x2b, 0x62, 0x31, 0x32, 0x38, 0x61, 0x35, 0x36, 0x39, 0xd, 0xa, 0x56, 0x69, 0x61, 0x3a, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x31, 0x31, 0x2e, 0x31, 0x31, 0x31, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x2b, 0x32, 0x31, 0x66, 0x31, 0x31, 0x33, 0x65, 0x37, 0x65, 0x33, 0x64, 0x30, 0x34, 0x63, 0x38, 0x34, 0x36, 0x31, 0x34, 0x38, 0x61, 0x39, 0x61, 0x64, 0x37, 0x36, 0x30, 0x37, 0x61, 0x65, 0x66, 0x61, 0x31, 0x2b, 0x36, 0x64, 0x66, 0x63, 0x66, 0x66, 0x65, 0x38, 0x2b, 0x31, 0xd, 0xa, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x37, 0x38, 0xd, 0xa, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x64, 0x70, 0xd, 0xa, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x31, 0x30, 0x30, 0x72, 0x65, 0x6c, 0x2c, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x72, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x65, 0x6e, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x64, 0x70, 0x2c, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x73, 0x75, 0x70, 0x2c, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61, 0x72, 0x74, 0x2f, 0x6d, 0x69, 0x78, 0x65, 0x64, 0xd, 0xa, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x3a, 0x20, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x2c, 0x20, 0x41, 0x43, 0x4b, 0x2c, 0x20, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x2c, 0x20, 0x42, 0x59, 0x45, 0x2c, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x2c, 0x20, 0x4e, 0x4f, 0x54, 0x49, 0x46, 0x59, 0x2c, 0x20, 0x50, 0x52, 0x41, 0x43, 0x4b, 0x2c, 0x20, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x2c, 0x20, 0x49, 0x4e, 0x46, 0x4f, 0x2c, 0x20, 0x52, 0x45, 0x46, 0x45, 0x52, 0xd, 0xa, 0xd, 0xa, 0x76, 0x3d, 0x30, 0xd, 0xa, 0x6f, 0x3d, 0x2d, 0x20, 0x30, 0x20, 0x30, 0x20, 0x49, 0x4e, 0x20, 0x49, 0x50, 0x34, 0x20, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0xd, 0xa, 0x73, 0x3d, 0x2d, 0xd, 0xa, 0x63, 0x3d, 0x49, 0x4e, 0x20, 0x49, 0x50, 0x34, 0x20, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0xd, 0xa, 0x74, 0x3d, 0x30, 0x20, 0x30, 0xd, 0xa, 0x6d, 0x3d, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x20, 0x30, 0x20, 0x52, 0x54, 0x50, 0x2f, 0x41, 0x56, 0x50, 0x20, 0x38}
	sniffer.worker.OnHEPPacket(hepPacket)
	return nil
}

func (sniffer *SnifferSetup) Run() error {
	var (
		loopCount   = 1
		lastPktTime *time.Time
		retError    error
	)

LOOP:
	for sniffer.isAlive {

		if sniffer.config.OneAtATime {
			fmt.Println("Press enter to read next packet")
			fmt.Scanln()
		}

		if sniffer.isCollector {

			if sniffer.isCollectorTcp {
				for {
					// Listen for an incoming connection.
					conn, err := sniffer.collectorTCPconn.Accept()
					if err != nil {
						logp.Err("Error accepting tcp connection: ", err.Error())
						continue
					}
					// Handle connections in a new goroutine.
					go sniffer.handleRequestExtended(conn)
				}

			} else {
				message := make([]byte, 5000)
				rlen, remote, err := sniffer.collectorUDPconn.ReadFromUDP(message[:])
				if err != nil {
					retError = fmt.Errorf("collector error: %s", err)
					sniffer.isAlive = false
					continue
				}

				logp.Debug("collector", fmt.Sprintf("received hep data from %s\n", remote))

				if bytes.HasPrefix(message, []byte{0x48, 0x45, 0x50, 0x33}) {
					//counter
					atomic.AddUint64(&sniffer.hepUDPCount, 1)

					//If we wanna filter only SIP
					if sniffer.collectOnlySIP {
						hep, err := decoder.DecodeHEP(message[:rlen])
						if err != nil {
							logp.Err("Bad HEP!")
						}
						if hep.ProtoType != 1 {
							logp.Debug("collector", "this is non sip")
							continue
						} else {
							//counter
							atomic.AddUint64(&sniffer.hepSIPCount, 1)
						}
					}
					sniffer.worker.OnHEPPacket(message[:rlen])
				} else {
					//counter
					atomic.AddUint64(&sniffer.unknownCount, 1)
				}
			}

		} else {

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
	case "collector":
		if sniffer.isCollectorTcp {
			sniffer.collectorTCPconn.Close()
		} else {
			sniffer.collectorUDPconn.Close()
		}
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

			case "collector":
				logp.Info("HEP collector Stats {HEPTcp:%d, HEPUdp:%d, HEPSip: %d, HEPDrops: %d}", sniffer.hepTcpCount, sniffer.hepUDPCount, sniffer.hepSIPCount, sniffer.unknownCount)
			}

		case <-signals:
			logp.Info("Sniffer received stop signal")
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}
	}
}

// Handles incoming tcp requests.
func (sniffer *SnifferSetup) handleRequestSimple(conn net.Conn) {

	for {

		// Make a buffer for HEP header.
		message := make([]byte, 10)

		// Read the incoming connection into the buffer.
		_, err := conn.Read(message)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			break
		}

		logp.Debug("collector", "received hep data in tcp")

		if bytes.HasPrefix(message, []byte{0x48, 0x45, 0x50, 0x33}) {

			//counter
			atomic.AddUint64(&sniffer.hepTcpCount, 1)

			length := binary.BigEndian.Uint16(message[4:6])
			data := make([]byte, length-10)

			// Read the incoming connection into the buffer.
			_, err := conn.Read(data)
			if err != nil {
				fmt.Println("Error reading:", err.Error())
				break
			}

			message = append(message, data...)

			//If we wanna filter only SIP
			if sniffer.collectOnlySIP {
				hep, err := decoder.DecodeHEP(message)
				if err != nil {
					logp.Err("Bad HEP!")
				}
				if hep.ProtoType != 1 {
					logp.Debug("collector", "this is non sip")
					continue
				} else {
					//counter
					atomic.AddUint64(&sniffer.hepSIPCount, 1)
				}
			}
			sniffer.worker.OnHEPPacket(message)
		} else {
			//counter
			atomic.AddUint64(&sniffer.unknownCount, 1)
		}
	}

	// Close the connection when you're done with it.
	conn.Close()
}

// Handles incoming tcp requests.
func (sniffer *SnifferSetup) handleRequestExtended(conn net.Conn) {

	var bufferPool bytes.Buffer
	message := make([]byte, 3000)
	for {

		// Read the incoming connection into the buffer.
		n, err := conn.Read(message)
		if err != nil {
			logp.Err("closed tcp connection [1]:", err.Error())
			break
		}

		bufferPool.Write(message[:n])

		for {

			logp.Debug("collector", "received hep data in tcp")
			dataHeader := make([]byte, 10)

			n, err := bufferPool.Read(dataHeader)
			if err != nil {
				if err.Error() != "EOF" {
					logp.Err("error during read buffer: ", err)
				}
				break
			}

			if n < 10 {
				logp.Debug("sniffer", "error during read buffer len")
				break
			}

			if bytes.HasPrefix(dataHeader, []byte{0x48, 0x45, 0x50, 0x33}) {

				length := binary.BigEndian.Uint16(dataHeader[4:6])

				for {

					if int(length) <= (bufferPool.Len() - 10) {

						dataHeader = append(dataHeader, bufferPool.Next(int(length)-10)...)

						//If we wanna filter only SIP
						if sniffer.collectOnlySIP {
							hep, err := decoder.DecodeHEP(dataHeader)
							if err != nil {
								logp.Err("Bad HEP!")
							}
							if hep.ProtoType != 1 {
								logp.Debug("collector", "this is non sip")
								break
							} else {
								//counter
								atomic.AddUint64(&sniffer.hepSIPCount, 1)
							}
						}
						//counter
						atomic.AddUint64(&sniffer.hepTcpCount, 1)
						//send out
						sniffer.worker.OnHEPPacket(dataHeader)
						break

					} else {

						// Read the incoming connection into the buffer.
						n, err := conn.Read(message)
						if err != nil {
							logp.Err("closed tcp connection [2]:", err.Error())
							bufferPool.Reset()
							break
						}

						bufferPool.Write(message[:n])
					}
				}
			} else {
				//counter
				atomic.AddUint64(&sniffer.unknownCount, 1)
			}
		}
	}

	// Close the connection when you're done with it.
	conn.Close()
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
