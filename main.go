package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/sniffer"
)

const version = "heplify 0.95"

func parseFlags() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", version, os.Args[0])
		flag.PrintDefaults()
	}

	var ifaceConfig config.InterfacesConfig
	var logging logp.Logging
	var fileRotator logp.FileRotator
	var rotateEveryKB uint64
	var keepLogFiles int

	flag.StringVar(&ifaceConfig.Device, "i", "any", "Listen on interface")
	flag.StringVar(&ifaceConfig.Type, "t", "pcap", "Capture types are [pcap, af_packet]")
	flag.StringVar(&ifaceConfig.ReadFile, "rf", "", "Read pcap file")
	flag.StringVar(&ifaceConfig.WriteFile, "wf", "", "Path to write pcap file")
	flag.IntVar(&ifaceConfig.RotationTime, "rt", 60, "Pcap rotation time in minutes")
	flag.BoolVar(&ifaceConfig.ZipPcap, "zf", false, "Gzip pcap file")
	flag.IntVar(&ifaceConfig.Loop, "lp", 1, "Loop count over ReadFile. Use 0 to loop forever")
	flag.BoolVar(&ifaceConfig.ReadSpeed, "rs", false, "Maximum pcap read speed. Doesn't use packet timestamps")
	flag.IntVar(&ifaceConfig.Snaplen, "s", 16384, "Snaplength")
	flag.StringVar(&ifaceConfig.PortRange, "pr", "5060-5090", "Portrange to capture SIP")
	flag.IntVar(&ifaceConfig.BufferSizeMb, "b", 64, "Interface buffersize (MB)")
	flag.IntVar(&keepLogFiles, "kl", 4, "Rotate the number of log files")
	flag.StringVar(&logging.Level, "l", "info", "Log level [debug, info, warning, error]")
	flag.BoolVar(&ifaceConfig.OneAtATime, "o", false, "Read packet for packet")
	flag.StringVar(&fileRotator.Path, "p", "./", "Log filepath")
	flag.StringVar(&fileRotator.Name, "n", "heplify.log", "Log filename")
	flag.Uint64Var(&rotateEveryKB, "r", 16384, "Log filesize (KB)")
	flag.StringVar(&config.Cfg.Mode, "m", "SIPRTCP", "Capture modes [SIPDNS, SIPLOG, SIPRTCP, SIP, TLS]")
	flag.BoolVar(&config.Cfg.Dedup, "dd", true, "Deduplicate packets")
	flag.StringVar(&config.Cfg.Filter, "fi", "", "Filter interesting packets")
	flag.StringVar(&config.Cfg.Discard, "di", "", "Discard uninteresting packets")
	flag.StringVar(&config.Cfg.HepServer, "hs", "127.0.0.1:9060", "HEP UDP server address")
	flag.UintVar(&config.Cfg.HepNodeID, "hi", 2002, "HEP NodeID")
	flag.Parse()

	config.Cfg.Iface = &ifaceConfig
	logging.Files = &fileRotator
	if logging.Files.Path != "" {
		tofiles := true
		logging.ToFiles = &tofiles

		rotateKB := rotateEveryKB * 1024
		logging.Files.RotateEveryBytes = &rotateKB
		logging.Files.KeepFiles = &keepLogFiles
	}
	config.Cfg.Logging = &logging

	if config.Cfg.HepNodeID > 0xFFFFFFFE {
		config.Cfg.HepNodeID = 0xFFFFFFFE
	}
}

func checkCritErr(err error) {
	if err != nil {
		fmt.Printf("\nCritical: %v\n\n", err)
		logp.Critical("%v", err)
		os.Exit(1)
	}
}

func main() {
	parseFlags()
	err := logp.Init("heplify", config.Cfg.Logging)
	checkCritErr(err)
	if os.Geteuid() != 0 {
		fmt.Printf("\nYou might need sudo or be root!\n\n")
		os.Exit(1)
	}

	capture := &sniffer.SnifferSetup{}
	err = capture.Init(false, config.Cfg.Mode, config.Cfg.Iface)
	checkCritErr(err)
	defer capture.Close()
	err = capture.Run()
	checkCritErr(err)
}
