package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
	"github.com/sipcapture/heplify/promstats"
	"github.com/sipcapture/heplify/sniffer"
)

const version = "heplify 1.66.7"

func createFlags() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", version, os.Args[0])
		flag.PrintDefaults()
	}

	var (
		err         error
		ifaceConfig config.InterfacesConfig
		logging     logp.Logging
		fileRotator logp.FileRotator
		dbg         string
		std         bool
		sys         bool
		fNum        int
		fSize       uint64
		hepfilter   string
	)

	//long
	flag.BoolVar(&config.Cfg.HEPBufferEnable, "hep-buffer-activate", false, "enable buffer messages if connection to HEP server broken")
	flag.BoolVar(&config.Cfg.HEPBufferDebug, "hep-buffer-debug", false, "enable debug buffer messages")
	flag.StringVar(&config.Cfg.HEPBufferSize, "hep-buffer-max-size", "0", "max buffer size, can be B, KB, MB, GB, TB. By default - unlimited")
	flag.StringVar(&config.Cfg.HEPBufferFile, "hep-buffer-file", "HEP-Buffer.dump", "filename and location for hep-buffer file")
	flag.StringVar(&config.Cfg.PrometheusIPPort, "prometheus", ":8090", "prometheus metrics - ip:port. By default all IPs")
	flag.BoolVar(&config.Cfg.CollectOnlySip, "collectonlysip", false, "collect only sip")
	flag.BoolVar(&config.Cfg.Reassembly, "tcpassembly", false, "If true, tcpassembly will be enabled")
	flag.BoolVar(&config.Cfg.SipAssembly, "sipassembly", false, "If true, sipassembly will be enabled")
	flag.UintVar(&config.Cfg.SendRetries, "tcpsendretries", 0, "Number of retries for sending before giving up and reconnecting")
	flag.UintVar(&config.Cfg.KeepAlive, "keepalive", 5, "keep alive internal - 5 seconds by default. 0 - disable")
	flag.BoolVar(&config.Cfg.Version, "version", false, "Show heplify version")
	flag.BoolVar(&config.Cfg.Protobuf, "protobuf", false, "Use Protobuf on wire")
	flag.BoolVar(&config.Cfg.SkipVerify, "skipverify", false, "skip certifcate validation")
	flag.BoolVar(&config.Cfg.Dedup, "dd", false, "Deduplicate packets")
	flag.StringVar(&config.Cfg.Discard, "di", "", "Discard uninteresting packets by any string")
	flag.StringVar(&config.Cfg.DiscardMethod, "dim", "", "Discard uninteresting SIP packets by Method [OPTIONS,NOTIFY]")
	flag.StringVar(&config.Cfg.DiscardIP, "diip", "", "Discard uninteresting SIP packets by Source or Destination IP(s)")
	flag.StringVar(&config.Cfg.DiscardSrcIP, "disip", "", "Discard uninteresting SIP packets by Source IP(s)")
	flag.StringVar(&config.Cfg.DiscardDstIP, "didip", "", "Discard uninteresting SIP packets by Destination IP(s)")
	flag.BoolVar(&ifaceConfig.WithVlan, "vlan", false, "vlan")
	flag.BoolVar(&ifaceConfig.WithErspan, "erspan", false, "erspan")
	flag.IntVar(&fNum, "fnum", 7, "The total num of log files to keep")
	flag.Uint64Var(&fSize, "fsize", 10*1024*1024, "The rotate size per log file based on byte")
	//scripts
	flag.StringVar(&config.Cfg.ScriptFile, "script-file", "", "Script file to execute on each packet")
	flag.StringVar(&hepfilter, "script-hep-filter", "1", "HEP filter for script, comma separated list of HEP types")
	//mtls
	flag.StringVar(&config.Mcfg.Crtpath, "crt-path", "./cert.pem", "Heplify agent mTLS certificate")
	flag.StringVar(&config.Mcfg.Keypath, "key-path", "./key.pem", "Heplify agent mTLS key")
	flag.StringVar(&config.Mcfg.Chainpath, "chain-path", "./chain.pem", "Heplify server mTLS cert chain")

	//short
	flag.StringVar(&config.Cfg.Filter, "fi", "", "Filter interesting packets by any string")
	flag.StringVar(&config.Cfg.HepCollector, "hin", "", "HEP collector address [udp:127.0.0.1:9093]")
	flag.StringVar(&config.Cfg.HepServer, "hs", "127.0.0.1:9060", "HEP server address")
	flag.StringVar(&config.Cfg.HepNodePW, "hp", "", "HEP node PW")
	flag.StringVar(&ifaceConfig.CustomBPF, "bpf", "", "Custom BPF to capture packets")
	//
	flag.UintVar(&config.Cfg.HepNodeID, "hi", 2002, "HEP node ID")
	flag.StringVar(&config.Cfg.HepNodeName, "hn", "", "HEP node Name")
	flag.StringVar(&config.Cfg.Network, "nt", "udp", "Network types are [udp, tcp, tls]")
	flag.UintVar(&ifaceConfig.FanoutID, "fg", 0, "Fanout group ID for af_packet")
	flag.IntVar(&ifaceConfig.FanoutWorker, "fw", 4, "Fanout worker count for af_packet")
	flag.StringVar(&ifaceConfig.ReadFile, "rf", "", "Read pcap file")
	flag.StringVar(&ifaceConfig.WriteFile, "wf", "", "Path to write pcap file")
	flag.IntVar(&ifaceConfig.RotationTime, "rt", 60, "Pcap rotation time in minutes")
	flag.BoolVar(&config.Cfg.Zip, "zf", false, "Enable pcap compression")
	flag.IntVar(&ifaceConfig.Loop, "lp", 1, "Loop count over ReadFile. Use 0 to loop forever")
	flag.BoolVar(&ifaceConfig.EOFExit, "eof-exit", false, "Exit on EOF of ReadFile")
	flag.BoolVar(&ifaceConfig.ReadSpeed, "rs", false, "Use packet timestamps with maximum pcap read speed")
	flag.StringVar(&ifaceConfig.PortRange, "pr", "5060-5090", "Portrange to capture SIP")
	flag.BoolVar(&sys, "sl", false, "Log to syslog")
	flag.IntVar(&ifaceConfig.BufferSizeMb, "b", 32, "Interface buffersize (MB)")
	flag.StringVar(&dbg, "d", "", "Enable certain debug selectors [defrag,layer,payload,rtp,rtcp,sdp]")
	flag.BoolVar(&std, "e", false, "Log to stderr and disable syslog/file output")
	flag.StringVar(&logging.Level, "l", "info", "Log level [debug, info, warning, error]")
	flag.BoolVar(&ifaceConfig.OneAtATime, "o", false, "Read packet for packet")
	flag.StringVar(&fileRotator.Path, "p", "./", "Log filepath")
	flag.StringVar(&fileRotator.Name, "n", "heplify.log", "Log filename")
	flag.StringVar(&config.Cfg.Mode, "m", "SIPRTCP", "Capture modes [SIP, SIPDNS, SIPLOG, SIPRTCP]")
	flag.IntVar(&ifaceConfig.Snaplen, "s", 8192, "Snaplength")
	flag.StringVar(&ifaceConfig.Device, "i", "any", "Listen on interface")
	flag.StringVar(&ifaceConfig.Type, "t", "af_packet", "Capture types are [pcap, af_packet]")
	flag.Parse()

	if hepfilter != "" {
		hepfilter = strings.Replace(hepfilter, " ", "", -1)
		for _, val := range strings.Split(hepfilter, ",") {
			intVal, err := strconv.Atoi(val)
			if err != nil {
				continue
			}
			config.Cfg.ScriptHEPFilter = append(config.Cfg.ScriptHEPFilter, intVal)
		}
	}

	config.Cfg.Iface = &ifaceConfig
	logp.ToStderr = &std
	logging.ToSyslog = &sys
	logp.DebugSelectorsStr = &dbg
	fileRotator.KeepFiles = &fNum
	fileRotator.RotateEveryBytes = &fSize
	logging.Files = &fileRotator
	config.Cfg.Logging = &logging

	if config.Cfg.HepNodeID > 0xFFFFFFFE {
		config.Cfg.HepNodeID = 0xFFFFFFFE
	}
	config.Cfg.Discard, err = strconv.Unquote(`"` + config.Cfg.Discard + `"`)
	checkErr(err)
	config.Cfg.Filter, err = strconv.Unquote(`"` + config.Cfg.Filter + `"`)
	checkErr(err)
}

func Human2FileSize(size string) (int64, error) {

	suffixes := [5]string{"B", "KB", "MB", "GB", "TB"} // Intialized with values
	var bytesSize int64

	for i, suffix := range suffixes {

		if i == 0 {
			continue
		}

		if strings.HasSuffix(size, suffix) {
			dataBytes := strings.TrimSuffix(size, suffix)
			baseVar, err := strconv.Atoi(dataBytes)
			if err != nil {
				return 0, err
			} else {
				bytesSize = int64(math.Pow(float64(1024), float64(i))) * int64(baseVar)
				return int64(bytesSize), nil
			}
		}
	}

	if strings.HasSuffix(size, "B") {

		dataBytes := strings.TrimSuffix(size, "B")
		baseVar, err := strconv.Atoi(dataBytes)
		if err != nil {
			return 0, err
		} else {
			return int64(baseVar), nil
		}
	}

	return bytesSize, fmt.Errorf("not found a valid suffix")
}

func checkErr(err error) {
	if err != nil {
		fmt.Printf("\nError: %v\n\n", err)
	}
}

func checkCritErr(err error) {
	if err != nil {
		fmt.Printf("\nCritical: %v\n\n", err)
		os.Exit(1)
	}
}

func main() {
	createFlags()

	if config.Cfg.Version {
		fmt.Println(version)
		os.Exit(0)
	}

	err := logp.Init("heplify", config.Cfg.Logging)
	checkCritErr(err)

	worker := 1
	if config.Cfg.Iface.Type == "af_packet" &&
		config.Cfg.Iface.FanoutID > 0 && config.Cfg.Iface.FanoutWorker > 1 {
		worker = config.Cfg.Iface.FanoutWorker
	}

	if config.Cfg.HEPBufferEnable && (config.Cfg.HEPBufferSize != "0" && config.Cfg.HEPBufferSize != "") {
		config.Cfg.MaxBufferSizeBytes, err = Human2FileSize(config.Cfg.HEPBufferSize)
		if err != nil {
			fmt.Println("couldn't convert buffer size to bytes", err)
			os.Exit(1)
		} else {
			fmt.Println("Maximum HEP file size is ", config.Cfg.MaxBufferSizeBytes, "bytes. You provided: ", config.Cfg.HEPBufferSize)
		}
	}

	var wg sync.WaitGroup

	go promstats.StartMetrics(&wg)

	for i := 0; i < worker; i++ {
		capture, err := sniffer.New(&config.Cfg)
		checkCritErr(err)

		defer func() {
			err = capture.Close()
			checkCritErr(err)
		}()

		wg.Add(1)
		go func() {

			if config.Cfg.HepNodePW != "" {
				capture.SendPing()
			}

			err = capture.Run()
			checkCritErr(err)
			wg.Done()
		}()
	}
	wg.Wait()
}
