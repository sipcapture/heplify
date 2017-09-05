package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/sniffer"
)

func optParse() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s [option]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var ifaceConfig config.InterfacesConfig
	var logging logp.Logging
	var fileRotator logp.FileRotator
	var rotateEveryKB uint64
	var keepLogFiles int

	flag.StringVar(&ifaceConfig.Device, "i", "", "Listen on interface")
	flag.StringVar(&ifaceConfig.Type, "t", "af_packet", "Capture types are [af_packet, pcap, file]")
	flag.StringVar(&ifaceConfig.BpfFilter, "f", "greater 300 and portrange 5060-5090", "BPF filter")
	flag.StringVar(&ifaceConfig.ReadFile, "rf", "", "Read packets from file. Please use -t file")
	flag.StringVar(&ifaceConfig.WriteFile, "wf", "", "Write packets to file. Please use -t file")
	flag.IntVar(&ifaceConfig.Loop, "lp", 0, "Loop")
	flag.BoolVar(&ifaceConfig.TopSpeed, "ts", false, "Topspeed uses timestamps from packets")
	flag.IntVar(&ifaceConfig.Snaplen, "s", 65535, "Snap length")
	flag.IntVar(&ifaceConfig.BufferSizeMb, "b", 64, "Interface buffersize (MB)")
	flag.IntVar(&keepLogFiles, "kl", 4, "Rotate the number of log files")
	flag.StringVar(&logging.Level, "l", "warning", "Log level [debug, info, notice, warning, error]")
	flag.BoolVar(&ifaceConfig.OneAtATime, "o", false, "Read packet for packet")
	flag.StringVar(&fileRotator.Path, "p", "./", "Log filepath")
	flag.StringVar(&fileRotator.Name, "n", "heplify.log", "Log filename")
	flag.Uint64Var(&rotateEveryKB, "r", 51200, "Log filesize (KB)")
	flag.BoolVar(&config.Cfg.HepDedup, "hd", false, "Deduplicate HEP packets")
	flag.StringVar(&config.Cfg.HepFilter, "hf", "", "Filter out REGISTER, OPTIONS ...")
	flag.StringVar(&config.Cfg.HepServer, "hs", "127.0.0.1:9060", "HEP Server address")

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
}

func init() {
	optParse()
	logp.Init("heplify", config.Cfg.Logging)
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Printf("\nYou might need sudo or be root!\n\n")
		os.Exit(1)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	capture := &sniffer.SnifferSetup{}
	err := capture.Init(false, config.Cfg.Iface.BpfFilter, sniffer.NewWorker, config.Cfg.Iface)
	if err != nil {
		fmt.Printf("\nCritical: %v\n\n", err)
		logp.Critical("%v", err)
	}
	defer capture.Close()
	err = capture.Run()
	if err != nil {
		fmt.Printf("\nCritical: %v\n\n", err)
		logp.Critical("%v", err)
	}
}
