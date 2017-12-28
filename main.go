package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"time"

	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/logp"
	"github.com/negbie/heplify/logp/configure"
	"github.com/negbie/heplify/sniffer"
)

const version = "heplify 0.97"

func parseFlags() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", version, os.Args[0])
		flag.PrintDefaults()
	}

	var ifaceConf config.InterfacesConfig

	flag.StringVar(&ifaceConf.Device, "i", "any", "Listen on interface")
	flag.StringVar(&ifaceConf.Type, "t", "pcap", "Capture types are [pcap, af_packet]")
	flag.StringVar(&ifaceConf.ReadFile, "rf", "", "Read pcap file")
	flag.StringVar(&ifaceConf.WriteFile, "wf", "", "Path to write pcap file")
	flag.IntVar(&ifaceConf.RotationTime, "rt", 60, "Pcap rotation time in minutes")
	flag.BoolVar(&config.Cfg.Zip, "zf", false, "Enable output compression")
	flag.IntVar(&ifaceConf.Loop, "lp", 1, "Loop count over ReadFile. Use 0 to loop forever")
	flag.BoolVar(&ifaceConf.ReadSpeed, "rs", false, "Maximum pcap read speed. Doesn't use packet timestamps")
	flag.IntVar(&ifaceConf.Snaplen, "s", 16384, "Snaplength")
	flag.StringVar(&ifaceConf.PortRange, "pr", "5060-5090", "Portrange to capture SIP")
	flag.IntVar(&ifaceConf.BufferSizeMb, "b", 64, "Interface buffersize (MB)")
	flag.BoolVar(&ifaceConf.OneAtATime, "o", false, "Read packet for packet")
	flag.BoolVar(&config.Cfg.Bench, "bm", false, "Benchmark for 2 min and exit")
	flag.StringVar(&config.Cfg.Mode, "m", "SIPRTCP", "Capture modes [SIPDNS, SIPLOG, SIP, SIPRTP, SIPRTCP, TLS]")
	flag.BoolVar(&config.Cfg.Dedup, "dd", true, "Deduplicate packets")
	flag.StringVar(&config.Cfg.Filter, "fi", "", "Filter interesting packets")
	flag.StringVar(&config.Cfg.Discard, "di", "", "Discard uninteresting packets")
	flag.StringVar(&config.Cfg.HepServer, "hs", "127.0.0.1:9060", "HEP UDP server address")
	flag.UintVar(&config.Cfg.HepNodeID, "hi", 2002, "HEP NodeID")
	flag.StringVar(&config.Cfg.NsqdTCPAddress, "ns", "", "NSQ TCP server address")
	flag.StringVar(&config.Cfg.NsqdTopic, "nt", "Kamailio-Topic", "NSQ publish topic")
	flag.Parse()

	config.Cfg.Iface = &ifaceConf

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

func benchmark() {
	go func() {
		cpuFile, err := os.Create("cpu.pprof")
		if err != nil {
			fmt.Printf("Could not create CPU profile: %v", err)
		}
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			fmt.Printf("Could not start CPU profile: %v", err)
		}

		traceFile, err := os.Create("trace.out")
		if err != nil {
			fmt.Printf("Could not create trace file: %v", err)
		}
		if err := trace.Start(traceFile); err != nil {
			fmt.Printf("Could not start trace: %v", err)
		}

		time.Sleep(120 * time.Second)
		ramFile, err := os.Create("ram.pprof")
		if err != nil {
			fmt.Printf("Could not create RAM profile: %vs", err)
		}
		runtime.GC() // update gc statistics
		if err := pprof.WriteHeapProfile(ramFile); err != nil {
			fmt.Printf("Could not write RAM profile: %v", err)
		}
		ramFile.Close()

		pprof.StopCPUProfile()
		cpuFile.Close()

		trace.Stop()
		traceFile.Close()

		fmt.Println("Benchmark finished!")
		os.Exit(1)
	}()
}

func main() {
	parseFlags()

	err := configure.Logging("heplify.log")
	checkCritErr(err)

	if os.Geteuid() != 0 {
		fmt.Printf("\nYou might need sudo or be root!\n\n")
		os.Exit(1)
	}

	capture := &sniffer.SnifferSetup{}
	defer capture.Close()
	err = capture.Init(false, config.Cfg.Mode, config.Cfg.Iface)
	checkCritErr(err)

	if config.Cfg.Bench {
		benchmark()
	}

	err = capture.Run()
	checkCritErr(err)
}
