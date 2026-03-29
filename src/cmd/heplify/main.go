package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/collector"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/promstats"
	"github.com/sipcapture/heplify/src/script"
	"github.com/sipcapture/heplify/src/sniffer"
	"github.com/sipcapture/heplify/src/transport"
)

// Command line flags
var (
	// General
	showVersion bool
	showHelp    bool
	configFile  string
	logLevel    string
	logFormat   string
	logStderr   bool
	logStdout   bool
	logJSON     bool

	// Interface
	device       string
	captureType  string
	snaplen      int
	bufferSizeMB int
	promisc      bool
	bpfFilter    string
	portRange    string

	// Modes
	captureMode string
	withVlan    bool
	withErspan  bool

	// HEP Server
	hepServer   string
	hepNodeID   uint
	hepNodeName string
	hepNodePW   string
	networkType string
	skipVerify  bool
	keepAlive   uint

	// Collector
	collectorAddr string

	// Filtering
	dedup          bool
	discardMethods string
	discardIPs     string
	discardSrcIPs  string
	discardDstIPs  string

	// PCAP
	readFile     string
	writeFile    string
	rotationTime int
	compressPcap bool

	// AF_PACKET
	fanoutID      uint
	fanoutWorkers int

	// Scripting
	scriptFile   string
	scriptFilter string

	// Buffer
	bufferEnable  bool
	bufferFile    string
	bufferMaxSize string
	bufferDebug   bool

	// Prometheus
	prometheusAddr string

	// TCP
	tcpAssembly bool
	sipAssembly bool

	// New flags
	filterInclude  string
	filterExclude  string
	debugSelectors string
	pcapMaxSpeed   bool
	pcapLoopCount  int
	pcapEOFExit    bool
	collectOnlySIP bool
	replaceToken   bool
	tcpSendRetries int
)

func init() {
	// General flags
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.StringVar(&configFile, "config", "", "Path to JSON config file (overrides command line flags)")
	flag.StringVar(&logLevel, "l", "info", "Log level [debug, info, warn, error]")
	flag.StringVar(&logLevel, "x", "info", "Log level [debug, info, warn, error]")
	flag.BoolVar(&logStderr, "e", true, "Log to stderr")
	flag.BoolVar(&logStdout, "S", false, "Log to stdout")
	flag.StringVar(&logFormat, "log-format", "text", "Log format [text|json]")

	// Interface flags
	flag.StringVar(&device, "i", "any", "Listen on interface")
	flag.StringVar(&captureType, "t", "af_packet", "Capture type [pcap, afpacket]")
	flag.IntVar(&snaplen, "s", 8192, "Snap length")
	flag.IntVar(&bufferSizeMB, "b", 32, "Interface buffer size (MB)")
	flag.BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	flag.StringVar(&bpfFilter, "bpf", "", "Custom BPF filter")
	flag.StringVar(&portRange, "pr", "5060-5090", "Port range to capture SIP")

	// Mode flags
	flag.StringVar(&captureMode, "m", "SIPRTCP", "Capture mode [SIP, SIPDNS, SIPLOG, SIPRTCP, SIPRTP]")
	flag.BoolVar(&withVlan, "vlan", false, "Enable VLAN support")
	flag.BoolVar(&withErspan, "erspan", false, "Enable ERSPAN support")

	// HEP Server flags
	flag.StringVar(&hepServer, "hs", "127.0.0.1:9060", "HEP server address (comma-separated for multiple)")
	flag.UintVar(&hepNodeID, "hi", 2002, "HEP node ID")
	flag.StringVar(&hepNodeName, "hn", "", "HEP node name")
	flag.StringVar(&hepNodePW, "hp", "", "HEP node password")
	flag.StringVar(&networkType, "nt", "udp", "Network type [udp, tcp, tls]")
	flag.BoolVar(&skipVerify, "skipverify", false, "Skip TLS certificate verification")
	flag.UintVar(&keepAlive, "keepalive", 5, "TCP keepalive interval (seconds), 0 to disable")

	// Collector flags
	flag.StringVar(&collectorAddr, "hin", "", "HEP collector address to receive HEP [udp:0.0.0.0:9060]")

	// Filtering flags
	flag.BoolVar(&dedup, "dd", false, "Enable packet deduplication")
	flag.StringVar(&discardMethods, "dim", "", "Discard SIP methods (comma-separated) [OPTIONS,NOTIFY]")
	flag.StringVar(&discardIPs, "diip", "", "Discard packets by IP (src or dst)")
	flag.StringVar(&discardSrcIPs, "disip", "", "Discard packets by source IP")
	flag.StringVar(&discardDstIPs, "didip", "", "Discard packets by destination IP")

	// PCAP flags
	flag.StringVar(&readFile, "rf", "", "Read from pcap file")
	flag.StringVar(&writeFile, "wf", "", "Write to pcap file")
	flag.IntVar(&rotationTime, "rt", 60, "PCAP rotation time (minutes)")
	flag.BoolVar(&compressPcap, "zf", false, "Compress pcap files with gzip")

	// AF_PACKET flags
	flag.UintVar(&fanoutID, "fg", 0, "Fanout group ID for af_packet")
	flag.IntVar(&fanoutWorkers, "fw", 4, "Fanout worker count for af_packet")

	// Scripting flags
	flag.StringVar(&scriptFile, "script-file", "", "Lua script file")
	flag.StringVar(&scriptFilter, "script-hep-filter", "1", "HEP types to pass to script (comma-separated)")

	// Buffer flags
	flag.BoolVar(&bufferEnable, "hep-buffer-activate", false, "Enable HEP buffer on connection failure")
	flag.StringVar(&bufferFile, "hep-buffer-file", "HEP-Buffer.dump", "HEP buffer file path")
	flag.StringVar(&bufferMaxSize, "hep-buffer-max-size", "100MB", "Max buffer size [B, KB, MB, GB]")
	flag.BoolVar(&bufferDebug, "hep-buffer-debug", false, "Enable buffer debug logging")

	// Prometheus flags
	flag.StringVar(&prometheusAddr, "prometheus", ":9096", "Prometheus metrics address")

	// TCP flags
	flag.BoolVar(&tcpAssembly, "tcpassembly", false, "Enable TCP reassembly")
	flag.BoolVar(&sipAssembly, "sipassembly", false, "Enable SIP assembly for TCP")
	flag.IntVar(&tcpSendRetries, "tcpsendretries", 0, "Max TCP reconnect attempts (0 = unlimited)")

	// Filter flags
	flag.StringVar(&filterInclude, "fi", "", "Include filter: pass packet only if payload contains string")
	flag.StringVar(&filterExclude, "di", "", "Exclude filter: drop packet if payload contains string")
	flag.StringVar(&debugSelectors, "d", "", "Debug selectors (comma-separated): defrag,layer,payload,rtp,rtcp,sdp")

	// PCAP replay flags
	flag.BoolVar(&pcapMaxSpeed, "rs", false, "Replay pcap at max speed (ignore timestamps)")
	flag.IntVar(&pcapLoopCount, "lp", 1, "Number of pcap replay loops (0=infinite)")
	flag.BoolVar(&pcapEOFExit, "eof-exit", false, "Exit when pcap replay reaches EOF")

	// Collector flags
	flag.BoolVar(&collectOnlySIP, "collectonlysip", false, "In collector mode, accept only HEP ProtoType=1 (SIP)")
	flag.BoolVar(&replaceToken, "replacetoken", false, "Replace NodePW in forwarded HEP packets (collector mode)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "heplify v%s (built %s, commit %s)\n\n", Version, BuildDate, GitCommit)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -i eth0 -hs 192.168.1.1:9060\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i eth0 -hs 192.168.1.1:9060 -l debug -log-format=json -S\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i eth0 -hs 192.168.1.1:9060 -nt tls -skipverify\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i eth0 -hs \"192.168.1.1:9060,192.168.2.2:9060\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -rf capture.pcap -hs 192.168.1.1:9060\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -config /etc/heplify/config.json\n", os.Args[0])
	}
}

func main() {
	flag.Parse()
	if logStdout {
		logStderr = false
	}

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if showVersion {
		printVersion()
		os.Exit(0)
	}

	// Setup logger
	logFormat = strings.TrimSpace(strings.ToLower(logFormat))
	switch logFormat {
	case "json", "text":
		logJSON = logFormat == "json"
	default:
		flag.Usage()
		log.Fatal().Str("value", logFormat).Msg("Invalid -log-format value, use text|json")
	}

	setupLogger()

	log.Info().
		Str("version", Version).
		Str("build_date", BuildDate).
		Str("git_commit", GitCommit).
		Str("go_version", runtime.Version()).
		Str("os_arch", runtime.GOOS+"/"+runtime.GOARCH).
		Msg("Starting heplify")

	var cfg *config.Config
	var err error

	// Load config from file or build from flags
	if configFile != "" {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			log.Fatal().Err(err).Str("file", configFile).Msg("Failed to load config")
		}
		log.Info().Str("file", configFile).Msg("Loaded config from file")
	} else {
		cfg = buildConfigFromFlags()
		log.Info().Msg("Using command line configuration")
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Configuration validation failed")
	}

	// Start Prometheus metrics
	if cfg.PrometheusSettings.Active {
		promstats.StartMetrics(cfg)
		log.Info().
			Str("addr", fmt.Sprintf("%s:%d", cfg.PrometheusSettings.Host, cfg.PrometheusSettings.Port)).
			Msg("Started Prometheus metrics")
	}

	// Initialize Lua scripting
	var scriptEngine *script.Engine
	if cfg.ScriptSettings.Active && cfg.ScriptSettings.File != "" {
		scriptEngine = script.New(cfg)
		if err := scriptEngine.LoadScript(cfg.ScriptSettings.File); err != nil {
			log.Error().Err(err).Str("file", cfg.ScriptSettings.File).Msg("Failed to load script")
		} else {
			log.Info().Str("file", cfg.ScriptSettings.File).Msg("Loaded Lua script")
			// Watch SIGHUP to reload script without restart
			scriptEngine.WatchSIGHUP()
		}
	} else {
		scriptEngine = script.New(cfg)
	}

	// Initialize transport (HEP sender)
	sender := transport.New(cfg)

	// Start sniffer and wire sender
	sniff := sniffer.New(cfg, scriptEngine)
	sniff.SetSender(sender)
	if err := sniff.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start sniffer")
	}
	log.Info().Msg("Started packet capture")

	// Start collector if configured, wire sender
	coll := collector.New(cfg)
	coll.SetSender(sender)
	if err := coll.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to start collector")
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	// Cleanup
	if coll != nil {
		coll.Stop()
	}
	if sender != nil {
		sender.Close()
	}
	if scriptEngine != nil {
		scriptEngine.Close()
	}

	log.Info().Msg("heplify stopped")
}

func setupLogger() {
	// Set log level
	switch strings.ToLower(logLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn", "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Setup output
	out := os.Stderr
	if logStdout {
		out = os.Stdout
	}
	if logJSON {
		log.Logger = zerolog.New(out).With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{
			Out: out,
			FieldsOrder: []string{
				"source", "destination",
				"interface", "addr", "transport",
				"num", "proto", "proto_type",
				"payload", "payload_hex", "bytes",
				"filter", "component", "reason",
			},
		}).With().Timestamp().Logger()
	}
}

func buildConfigFromFlags() *config.Config {
	cfg := &config.Config{}

	// Parse HEP servers
	servers := strings.Split(hepServer, ",")
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		var host string
		port := 9060
		if h, p, err := net.SplitHostPort(server); err == nil {
			host = h
			if parsed, err := strconv.Atoi(p); err == nil {
				port = parsed
			}
		} else {
			host = server
		}

		cfg.TransportSettings = append(cfg.TransportSettings, config.TransportSettings{
			Name:       fmt.Sprintf("hep-%s", server),
			Active:     true,
			Protocol:   "HEPv3",
			Host:       host,
			Port:       port,
			Transport:  networkType,
			Password:   hepNodePW,
			SkipVerify: skipVerify,
			KeepAlive:  int(keepAlive),
			MaxRetries: tcpSendRetries,
		})
	}

	// Socket settings
	socketType := "afpacket"
	if captureType == "pcap" {
		socketType = "pcap"
	}

	// Parse collector address
	collectorHost := ""
	collectorPort := 0
	collectorProto := ""
	if collectorAddr != "" {
		// Format: proto:host:port
		parts := strings.Split(collectorAddr, ":")
		if len(parts) >= 3 {
			collectorProto = parts[0]
			collectorHost = parts[1]
			if p, err := strconv.Atoi(parts[2]); err == nil {
				collectorPort = p
			}
		}
	}

	cfg.SocketSettings = []config.SocketSettings{
		{
			Name:           "capture",
			Active:         true,
			SocketType:     socketType,
			Device:         device,
			Promisc:        promisc,
			SnapLen:        snaplen,
			BufferSizeMB:   bufferSizeMB,
			Vlan:           withVlan,
			Erspan:         withErspan,
			BPFFilter:      bpfFilter,
			PcapFile:       readFile,
			FanoutID:       uint16(fanoutID),
			FanoutWorkers:  fanoutWorkers,
			TcpReasm:       tcpAssembly,
			SIPReasm:       sipAssembly,
			CaptureMode:    parseCaptureMode(captureMode),
			CollectorHost:  collectorHost,
			CollectorPort:  collectorPort,
			CollectorProto: collectorProto,
		},
	}

	// Protocol settings based on port range
	minPort, maxPort, err := parsePortRange(portRange)
	if err != nil {
		log.Warn().Err(err).Str("range", portRange).Msg("Invalid port range, using default 5060-5090")
		minPort, maxPort = 5060, 5090
	}
	cfg.ProtocolSettings = []config.ProtocolSettings{
		{
			Name:     "SIP",
			MinPort:  minPort,
			MaxPort:  maxPort,
			Protocol: []string{"udp", "tcp"},
		},
	}

	// SIP settings
	cfg.SipSettings.Deduplicate = dedup
	cfg.SipSettings.DiscardMethods = parseCSV(discardMethods)
	cfg.SipSettings.DiscardIPs = parseCSV(discardIPs)
	cfg.SipSettings.DiscardSrcIP = parseCSV(discardSrcIPs)
	cfg.SipSettings.DiscardDstIP = parseCSV(discardDstIPs)

	// HEP settings
	cfg.HepSettings.HepV3Active = true
	cfg.HepSettings.Deduplicate = dedup

	// System settings
	cfg.SystemSettings.NodeName = hepNodeName
	cfg.SystemSettings.NodeID = uint32(hepNodeID)
	cfg.SystemSettings.NodePW = hepNodePW
	if cfg.SystemSettings.NodeName == "" {
		hostname, _ := os.Hostname()
		cfg.SystemSettings.NodeName = hostname
	}

	// Filter settings
	if filterInclude != "" {
		cfg.FilterInclude = parseCSV(filterInclude)
	}
	if filterExclude != "" {
		cfg.FilterExclude = parseCSV(filterExclude)
	}
	if debugSelectors != "" {
		cfg.DebugSelectors = parseCSV(debugSelectors)
	}

	// HEP settings
	cfg.HepSettings.CollectOnlySIP = collectOnlySIP
	cfg.HepSettings.ReplaceToken = replaceToken

	// Prometheus settings
	cfg.PrometheusSettings.Active = prometheusAddr != ""
	if prometheusAddr != "" {
		parts := strings.Split(prometheusAddr, ":")
		if len(parts) >= 2 {
			cfg.PrometheusSettings.Host = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil {
				cfg.PrometheusSettings.Port = p
			}
		}
		if cfg.PrometheusSettings.Port == 0 {
			cfg.PrometheusSettings.Port = 9096
		}
	}

	// Script settings
	cfg.ScriptSettings.Active = scriptFile != ""
	cfg.ScriptSettings.File = scriptFile
	cfg.ScriptSettings.HEPFilter = scriptFilter

	// PCAP settings
	cfg.PcapSettings.WriteEnable = writeFile != ""
	cfg.PcapSettings.WritePath = writeFile
	cfg.PcapSettings.RotateMinutes = rotationTime
	cfg.PcapSettings.Compress = compressPcap
	cfg.PcapSettings.MaxSpeed = pcapMaxSpeed
	cfg.PcapSettings.LoopCount = pcapLoopCount
	cfg.PcapSettings.EOFExit = pcapEOFExit

	// Buffer settings
	cfg.BufferSettings.Enable = bufferEnable
	cfg.BufferSettings.File = bufferFile
	cfg.BufferSettings.MaxSizeBytes = parseSize(bufferMaxSize)
	cfg.BufferSettings.Debug = bufferDebug

	// Log settings
	cfg.LogSettings.Active = true
	cfg.LogSettings.Level = logLevel
	cfg.LogSettings.Stdout = logStdout
	cfg.LogSettings.Json = logJSON

	return cfg
}

func parseCaptureMode(mode string) []string {
	switch strings.ToUpper(mode) {
	case "SIP":
		return []string{"SIP"}
	case "SIPDNS":
		return []string{"SIP", "DNS"}
	case "SIPLOG":
		return []string{"SIP", "LOG"}
	case "SIPRTCP":
		return []string{"SIP", "RTCP"}
	case "SIPRTP":
		return []string{"SIP", "RTP"}
	default:
		return []string{"SIP", "RTCP"}
	}
}

func parsePortRange(pr string) (uint16, uint16, error) {
	parts := strings.Split(pr, "-")
	minInt, maxInt := 5060, 5090
	if len(parts) >= 1 {
		parsed, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid min port: %w", err)
		}
		minInt = parsed
	}
	if len(parts) >= 2 {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid max port: %w", err)
		}
		maxInt = parsed
	}
	if minInt < 1 || maxInt > 65535 || minInt > maxInt {
		return 0, 0, fmt.Errorf("port range out of bounds: %d-%d", minInt, maxInt)
	}
	return uint16(minInt), uint16(maxInt), nil
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseSize(s string) int64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	multipliers := map[string]int64{
		"TB": 1024 * 1024 * 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"MB": 1024 * 1024,
		"KB": 1024,
		"B":  1,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			if n, err := strconv.ParseInt(numStr, 10, 64); err == nil {
				return n * mult
			}
			return 0
		}
	}

	// Default: try parsing as bytes
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
