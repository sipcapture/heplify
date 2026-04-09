package main

import (
	"crypto/rand"
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
	"github.com/sipcapture/heplify/src/apiserver"
	"github.com/sipcapture/heplify/src/collector"
	"github.com/sipcapture/heplify/src/config"
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
	noConfig    bool
	logLevel    string
	logFormat   string
	logStderr   bool
	logStdout   bool
	logJSON     bool

	// Interface
	device        string
	captureType   string
	snaplen       int
	bufferSizeMB  int
	promisc       bool
	promiscIfaces string
	bpfFilter     string
	portRange     string

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

	// Prometheus metrics server
	prometheusAddr string

	// API / Web stats server
	apiAddr string
	apiUser string
	apiPass string

	// TCP
	tcpAssembly bool
	sipAssembly bool

	// Filter / debug
	filterInclude  string
	filterExclude  string
	debugSelectors string
	pcapMaxSpeed   bool
	pcapLoopCount  int
	pcapEOFExit    bool
	collectOnlySIP bool
	replaceToken   bool
	tcpSendRetries int

	// Socket extras
	ipFragment bool

	// Logging extras
	logPayload bool

	// Debug settings
	disableDefrag   bool
	disableTcpReasm bool

	// API TLS
	apiTLS      bool
	apiCertFile string
	apiKeyFile  string
)

func init() {
	// General flags
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.StringVar(&configFile, "config", "", "Path to JSON config file (explicitly set CLI flags override file values)")
	flag.BoolVar(&noConfig, "no-config", false, "Ignore both -config and HEPLIFY_CONFIG; use CLI settings only")
	flag.StringVar(&logLevel, "l", "info", "Log level [debug, info, warn, error]")
	flag.BoolVar(&logStderr, "e", true, "Log to stderr")
	flag.BoolVar(&logStdout, "S", false, "Log to stdout")
	flag.StringVar(&logFormat, "log-format", "text", "Log format [text|json]")

	// Interface flags
	flag.StringVar(&device, "i", "any", "Listen on interface")
	flag.StringVar(&captureType, "t", "afpacket", "Capture type [pcap, afpacket]")
	flag.IntVar(&snaplen, "s", 8192, "Snap length")
	flag.IntVar(&bufferSizeMB, "b", 32, "Interface buffer size (MB)")
	flag.BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	flag.StringVar(&promiscIfaces, "pi", "", "Comma-separated interfaces to put into promisc when -i any (e.g. eth0,eth1)")
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
	flag.StringVar(&writeFile, "wf", "", "Write packets to pcap (output directory)")
	flag.IntVar(&rotationTime, "rt", 60, "PCAP rotation time in minutes")
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
	flag.StringVar(&prometheusAddr, "prometheus", "", "Prometheus /metrics server address, e.g. :9096 (empty = disabled)")

	// API / Web stats flags
	flag.StringVar(&apiAddr, "api", "", "API server address, e.g. :9060 (empty = disabled)")
	flag.StringVar(&apiUser, "api-user", "", "Username for web stats Basic Auth (empty = no auth)")
	flag.StringVar(&apiPass, "api-pass", "", "Password for web stats Basic Auth")

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

	// Socket extras
	flag.BoolVar(&ipFragment, "ipfragment", false, "Enable IP fragment reassembly")

	// Logging extras
	flag.BoolVar(&logPayload, "log-payload", false, "Print SIP payload as plain text in debug logs")

	// Debug settings
	flag.BoolVar(&disableDefrag, "disable-defrag", false, "Disable IP defragmentation")
	flag.BoolVar(&disableTcpReasm, "disable-tcp-reasm", false, "Disable TCP reassembly processing")

	// API TLS flags
	flag.BoolVar(&apiTLS, "api-tls", false, "Enable HTTPS for API (requires -api-cert and -api-key)")
	flag.StringVar(&apiCertFile, "api-cert", "", "TLS certificate file for API")
	flag.StringVar(&apiKeyFile, "api-key", "", "TLS key file for API")

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
		fmt.Fprintf(os.Stderr, "  %s -config /etc/heplify/heplify.json\n", os.Args[0])
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

	var fromEnv bool
	configFile, fromEnv = resolveConfigFilePath(configFile, noConfig)
	if noConfig {
		log.Info().Msg("Configuration file loading is disabled by -no-config")
	} else if configFile != "" && fromEnv {
		log.Info().Str("file", configFile).Msg("Using config file from HEPLIFY_CONFIG env var")
	}

	// Load config from file or build from flags
	if configFile != "" {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			log.Fatal().Err(err).Str("file", configFile).Msg("Failed to load config")
		}
		log.Info().Str("file", configFile).Msg("Loaded config from file")
		// Explicitly-set CLI flags take precedence over the config file.
		// This preserves backward-compatible behaviour: users can keep a default
		// config in /etc/heplify/heplify.json (or via HEPLIFY_CONFIG) and still
		// override individual settings on the command line (e.g. -i ens32 -erspan).
		applyExplicitCLIOverrides(cfg)
	} else {
		cfg = buildConfigFromFlags()
		log.Info().Msg("Using command line configuration")
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Configuration validation failed")
	}
	logEffectiveRuntimeConfig(cfg)

	// Start API / Prometheus metrics server
	apiserver.StartMetrics(cfg)

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
	// globalSender uses all active transports; used by the collector and as fallback.
	globalSender := transport.New(cfg)

	// Start sniffer and wire per-socket senders
	sniff := sniffer.New(cfg, scriptEngine)
	// Set global fallback first (used by syslog capture and sockets with no transport_profile)
	sniff.SetSender(globalSender)
	for _, sock := range cfg.SocketSettings {
		// Skip per-socket sender when the profile is empty or covers all active transports —
		// in both cases the socket reuses globalSender via the fallback set above,
		// avoiding a duplicate connection to the same HEP server.
		if len(sock.TransportProfile) == 0 || coversAllActiveTransports(sock.TransportProfile, cfg.TransportSettings) {
			continue
		}
		s := buildSenderForSocket(cfg, sock)
		sniff.SetSenderForSocket(sock.Name, s)
	}
	if err := sniff.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start sniffer")
	}
	log.Info().Msg("Started packet capture")

	// Register web stats getter for /api/stats endpoint
	if cfg.ApiSettings.Active {
		apiserver.RegisterStatsGetter(func() apiserver.WebStats {
			snap := sniff.GetStats().Snapshot()
			ifaces := make([]string, 0, len(cfg.SocketSettings))
			capModes := make(map[string][]string)
			for _, s := range cfg.SocketSettings {
				ifaces = append(ifaces, s.Device)
				capModes[s.Device] = s.CaptureMode
			}
			ws := apiserver.WebStats{
				NodeName:      cfg.SystemSettings.NodeName,
				NodeID:        int(cfg.SystemSettings.NodeID),
				UUID:          cfg.SystemSettings.UUID,
				Interfaces:    ifaces,
				CaptureModes:  capModes,
				UptimeSeconds: snap.UptimeSeconds,
				Uptime:        sniffer.FormatUptime(snap.UptimeSeconds),
			}
			ws.Packets.Total = snap.Total
			ws.Packets.SIP = snap.SIP
			ws.Packets.RTCP = snap.RTCP
			ws.Packets.RTCPFail = snap.RTCPFail
			ws.Packets.RTP = snap.RTP
			ws.Packets.DNS = snap.DNS
			ws.Packets.Log = snap.Log
			ws.Packets.HEPSent = snap.HEPSent
			ws.Packets.Duplicates = snap.Duplicates
			ws.Packets.Unknown = snap.Unknown
			return ws
		})
	}

	// Start collector if configured, wire sender
	coll := collector.New(cfg)
	coll.SetSender(globalSender)
	if err := coll.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to start collector")
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	// Cleanup: close packet sources first so that capture goroutines return and
	// their deferred cleanup (e.g. restoring promiscuous mode) is executed.
	sniff.Stop()
	if coll != nil {
		coll.Stop()
	}
	if globalSender != nil {
		globalSender.Close()
	}
	if scriptEngine != nil {
		scriptEngine.Close()
	}

	log.Info().Msg("heplify stopped")
}

func resolveConfigFilePath(current string, skip bool) (string, bool) {
	if skip {
		return "", false
	}
	if current != "" {
		return current, false
	}
	envPath := os.Getenv("HEPLIFY_CONFIG")
	if envPath != "" {
		return envPath, true
	}
	return "", false
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
	switch strings.ToLower(captureType) {
	case "pcap":
		socketType = "pcap"
	case "afpacket", "af_packet":
		socketType = "afpacket"
	default:
		log.Warn().Str("value", captureType).Msg("Unknown capture type, falling back to afpacket. Valid values: pcap, afpacket")
	}

	// Parse collector address: format is proto:host:port, e.g. "udp:0.0.0.0:9060" or "tcp:::1:9060"
	if collectorAddr != "" {
		protoEnd := strings.Index(collectorAddr, ":")
		if protoEnd > 0 {
			proto := collectorAddr[:protoEnd]
			rest := collectorAddr[protoEnd+1:]
			// rest is "host:port" — use net.SplitHostPort for correct IPv6 handling
			host, portStr, splitErr := net.SplitHostPort(rest)
			if splitErr != nil {
				log.Warn().Err(splitErr).Str("addr", collectorAddr).Msg("Invalid -hin address, expected proto:host:port")
			} else {
				cfg.CollectorSettings.Active = true
				cfg.CollectorSettings.Proto = proto
				cfg.CollectorSettings.Host = host
				if p, err := strconv.Atoi(portStr); err == nil {
					cfg.CollectorSettings.Port = p
				}
			}
		} else {
			log.Warn().Str("addr", collectorAddr).Msg("Invalid -hin address, expected proto:host:port e.g. udp:0.0.0.0:9060")
		}
	}

	cfg.SocketSettings = []config.SocketSettings{
		{
			Name:              "capture",
			Active:            true,
			SocketType:        socketType,
			Device:            device,
			Promisc:           promisc,
			PromiscInterfaces: parseCSV(promiscIfaces),
			SnapLen:           snaplen,
			BufferSizeMB:      bufferSizeMB,
			Vlan:              withVlan,
			Erspan:            withErspan,
			BPFFilter:         bpfFilter,
			PcapFile:          readFile,
			FanoutID:          uint16(fanoutID),
			FanoutWorkers:     fanoutWorkers,
			TcpReasm:          tcpAssembly,
			SIPReasm:          sipAssembly,
			CaptureMode:       parseCaptureMode(captureMode),
		},
	}

	// Protocol settings based on port range
	minPort, maxPort, err := parsePortRange(portRange)
	if err != nil {
		log.Warn().Err(err).Str("range", portRange).Msg("Invalid port range, using default 5060-5090")
		minPort, maxPort = 5060, 5090
	}
	cfg.ProtocolSettings = buildProtocolSettings(parseCaptureMode(captureMode), minPort, maxPort)

	// SIP settings
	cfg.SipSettings.Deduplicate = dedup
	cfg.SipSettings.DiscardMethods = parseCSV(discardMethods)
	cfg.SipSettings.DiscardIPs = parseCSV(discardIPs)
	cfg.SipSettings.DiscardSrcIP = parseCSV(discardSrcIPs)
	cfg.SipSettings.DiscardDstIP = parseCSV(discardDstIPs)

	// HEP settings
	cfg.HepSettings.Deduplicate = dedup

	// System settings
	cfg.SystemSettings.NodeName = hepNodeName
	cfg.SystemSettings.NodeID = uint32(hepNodeID)
	cfg.SystemSettings.NodePW = hepNodePW
	if cfg.SystemSettings.NodeName == "" {
		hostname, _ := os.Hostname()
		cfg.SystemSettings.NodeName = hostname
	}
	if cfg.SystemSettings.UUID == "" {
		cfg.SystemSettings.UUID = generateUUID()
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

	// RTCP settings: active by default when running from CLI
	cfg.RtcpSettings.Active = true

	// Prometheus settings
	cfg.PrometheusSettings.Active = prometheusAddr != ""
	if prometheusAddr != "" {
		full := prometheusAddr
		if strings.HasPrefix(prometheusAddr, ":") {
			full = "0.0.0.0" + prometheusAddr
		}
		hostPort := strings.SplitN(full, ":", 2)
		cfg.PrometheusSettings.Host = hostPort[0]
		if len(hostPort) == 2 {
			if p, err := strconv.Atoi(hostPort[1]); err == nil {
				cfg.PrometheusSettings.Port = p
			}
		}
	}

	// API / Web stats settings
	cfg.ApiSettings.Active = apiAddr != ""
	if apiAddr != "" {
		full := apiAddr
		if strings.HasPrefix(apiAddr, ":") {
			full = "0.0.0.0" + apiAddr
		}
		hostPort := strings.SplitN(full, ":", 2)
		cfg.ApiSettings.Host = hostPort[0]
		if len(hostPort) == 2 {
			if p, err := strconv.Atoi(hostPort[1]); err == nil {
				cfg.ApiSettings.Port = p
			}
		}
		if cfg.ApiSettings.Port == 0 {
			cfg.ApiSettings.Port = 9060
		}
		cfg.ApiSettings.Username = apiUser
		cfg.ApiSettings.Password = apiPass
	}

	// Script settings
	cfg.ScriptSettings.Active = scriptFile != ""
	cfg.ScriptSettings.File = scriptFile
	cfg.ScriptSettings.HEPFilter = scriptFilter

	// PCAP settings
	cfg.PcapSettings.WriteFile = writeFile
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
	cfg.LogSettings.LogPayload = logPayload

	// Socket extras
	cfg.SocketSettings[0].IpFragment = ipFragment

	// Debug settings
	cfg.DebugSettings.DisableIPDefrag = disableDefrag
	cfg.DebugSettings.DisableTcpReassembly = disableTcpReasm

	// API TLS settings
	if apiTLS {
		cfg.ApiSettings.TLS = true
		cfg.ApiSettings.CertFile = apiCertFile
		cfg.ApiSettings.KeyFile = apiKeyFile
	}

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
		log.Warn().Str("mode", mode).Msg("Unknown capture mode, falling back to SIPRTCP. Valid modes: SIP, SIPDNS, SIPLOG, SIPRTCP, SIPRTP")
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
	multipliers := []struct {
		suffix string
		mult   int64
	}{
		{suffix: "TB", mult: 1024 * 1024 * 1024 * 1024},
		{suffix: "GB", mult: 1024 * 1024 * 1024},
		{suffix: "MB", mult: 1024 * 1024},
		{suffix: "KB", mult: 1024},
		{suffix: "B", mult: 1},
	}

	for _, m := range multipliers {
		if strings.HasSuffix(s, m.suffix) {
			numStr := strings.TrimSuffix(s, m.suffix)
			if n, err := strconv.ParseInt(numStr, 10, 64); err == nil {
				return n * m.mult
			}
			return 0
		}
	}

	// Default: try parsing as bytes
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// buildProtocolSettings constructs ProtocolSettings for each protocol in captureMode.
// SIP uses the user-specified port range; RTCP/RTP use the standard media range 1024-65535.
func buildProtocolSettings(modes []string, sipMin, sipMax uint16) []config.ProtocolSettings {
	var ps []config.ProtocolSettings
	for _, m := range modes {
		switch m {
		case "SIP":
			ps = append(ps, config.ProtocolSettings{
				Name:        "SIP",
				MinPort:     sipMin,
				MaxPort:     sipMax,
				Protocol:    []string{"udp", "tcp"},
				Description: "SIP",
			})
		case "RTCP":
			ps = append(ps, config.ProtocolSettings{
				Name:        "RTCP",
				MinPort:     1024,
				MaxPort:     65535,
				Protocol:    []string{"udp"},
				Description: "RTCP",
			})
		case "RTP":
			ps = append(ps, config.ProtocolSettings{
				Name:        "RTP",
				MinPort:     1024,
				MaxPort:     65535,
				Protocol:    []string{"udp"},
				Description: "RTP",
			})
		case "DNS":
			ps = append(ps, config.ProtocolSettings{
				Name:        "DNS",
				MinPort:     53,
				MaxPort:     53,
				Protocol:    []string{"udp", "tcp"},
				Description: "DNS",
			})
		}
	}
	return ps
}

// coversAllActiveTransports returns true when every active transport in the config
// is listed in profile — meaning the socket's profile is equivalent to "all transports"
// and the socket can share globalSender instead of opening a duplicate connection.
func coversAllActiveTransports(profile []string, transports []config.TransportSettings) bool {
	profileSet := make(map[string]struct{}, len(profile))
	for _, p := range profile {
		profileSet[p] = struct{}{}
	}
	for _, t := range transports {
		if t.Active {
			if _, ok := profileSet[t.Name]; !ok {
				return false
			}
		}
	}
	return true
}

// buildSenderForSocket creates a Sender for the given socket.
// If socket.TransportProfile is non-empty, only the named transports are used;
// otherwise all active transports are used (backward-compatible behaviour).
func buildSenderForSocket(cfg *config.Config, sock config.SocketSettings) *transport.Sender {
	if len(sock.TransportProfile) == 0 {
		return transport.New(cfg)
	}
	var selected []config.TransportSettings
	for _, name := range sock.TransportProfile {
		for _, t := range cfg.TransportSettings {
			if t.Name == name {
				selected = append(selected, t)
				break
			}
		}
	}
	return transport.NewFromTransports(selected, cfg)
}

func applyTransportRuntimeOverrides(cfg *config.Config) {
	for i := range cfg.TransportSettings {
		cfg.TransportSettings[i].Transport = networkType
		cfg.TransportSettings[i].SkipVerify = skipVerify
		cfg.TransportSettings[i].KeepAlive = int(keepAlive)
		cfg.TransportSettings[i].MaxRetries = tcpSendRetries
	}
}

func applyCollectorAddrOverride(cfg *config.Config) {
	if collectorAddr == "" {
		cfg.CollectorSettings.Active = false
		cfg.CollectorSettings.Host = ""
		cfg.CollectorSettings.Port = 0
		cfg.CollectorSettings.Proto = ""
		return
	}
	protoEnd := strings.Index(collectorAddr, ":")
	if protoEnd <= 0 {
		log.Warn().Str("addr", collectorAddr).Msg("Invalid -hin address override, expected proto:host:port")
		return
	}
	proto := collectorAddr[:protoEnd]
	rest := collectorAddr[protoEnd+1:]
	host, portStr, splitErr := net.SplitHostPort(rest)
	if splitErr != nil {
		log.Warn().Err(splitErr).Str("addr", collectorAddr).Msg("Invalid -hin address override, expected proto:host:port")
		return
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		log.Warn().Err(convErr).Str("addr", collectorAddr).Msg("Invalid -hin port override")
		return
	}
	cfg.CollectorSettings.Active = true
	cfg.CollectorSettings.Proto = proto
	cfg.CollectorSettings.Host = host
	cfg.CollectorSettings.Port = port
}

func appendOverrideLogKV(overrideLog *[]string, key, value string) {
	*overrideLog = append(*overrideLog, key+"="+value)
}

func logEffectiveRuntimeConfig(cfg *config.Config) {
	activeSockets := 0
	socketNames := make([]string, 0, len(cfg.SocketSettings))
	socketDevices := make([]string, 0, len(cfg.SocketSettings))
	socketModes := make([]string, 0, len(cfg.SocketSettings))
	socketProfiles := make([]string, 0, len(cfg.SocketSettings))
	for _, s := range cfg.SocketSettings {
		if s.Active {
			activeSockets++
		}
		socketNames = append(socketNames, s.Name)
		socketDevices = append(socketDevices, s.Device)
		socketModes = append(socketModes, strings.Join(s.CaptureMode, "+"))
		if len(s.TransportProfile) == 0 {
			socketProfiles = append(socketProfiles, "<all>")
		} else {
			socketProfiles = append(socketProfiles, strings.Join(s.TransportProfile, ","))
		}
	}

	activeTransports := 0
	transportNames := make([]string, 0, len(cfg.TransportSettings))
	transportTargets := make([]string, 0, len(cfg.TransportSettings))
	transportKinds := make([]string, 0, len(cfg.TransportSettings))
	for _, t := range cfg.TransportSettings {
		if t.Active {
			activeTransports++
		}
		transportNames = append(transportNames, t.Name)
		transportTargets = append(transportTargets, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
		transportKinds = append(transportKinds, t.Transport)
	}

	log.Info().
		Int("sockets_total", len(cfg.SocketSettings)).
		Int("sockets_active", activeSockets).
		Strs("socket_names", socketNames).
		Strs("socket_devices", socketDevices).
		Strs("socket_capture_modes", socketModes).
		Strs("socket_transport_profiles", socketProfiles).
		Int("transports_total", len(cfg.TransportSettings)).
		Int("transports_active", activeTransports).
		Strs("transport_names", transportNames).
		Strs("transport_targets", transportTargets).
		Strs("transport_kinds", transportKinds).
		Bool("collector_active", cfg.CollectorSettings.Active).
		Bool("collect_only_sip", cfg.HepSettings.CollectOnlySIP).
		Bool("replace_token", cfg.HepSettings.ReplaceToken).
		Bool("deduplicate", cfg.HepSettings.Deduplicate).
		Bool("rtcp_active", cfg.RtcpSettings.Active).
		Bool("api_active", cfg.ApiSettings.Active).
		Bool("prometheus_active", cfg.PrometheusSettings.Active).
		Bool("script_active", cfg.ScriptSettings.Active).
		Bool("buffer_active", cfg.BufferSettings.Enable).
		Msg("Effective runtime configuration")
}

// applyExplicitCLIOverrides applies only the flags that the user explicitly set
// on the command line on top of a config loaded from a file. This allows
// "docker run ... -i ens32 -erspan" to override the interface/erspan setting in
// a default config without requiring the user to disable the config file entirely.
//
// flag.Visit iterates only over flags whose value was changed from the default,
// so default values never silently overwrite config file entries.
func applyExplicitCLIOverrides(cfg *config.Config) {
	var visited []string
	flag.Visit(func(f *flag.Flag) { visited = append(visited, f.Name) })
	applyExplicitCLIOverridesWithVisited(cfg, visited)
}

// applyExplicitCLIOverridesWithVisited is the testable core of
// applyExplicitCLIOverrides. It applies only the named flags (those that were
// explicitly set) to cfg, reading their current values from the package-level
// flag variables. Tests pass a controlled visited slice instead of relying on
// the global flag.CommandLine visited state.
func applyExplicitCLIOverridesWithVisited(cfg *config.Config, visited []string) {
	visitedSet := make(map[string]bool, len(visited))
	for _, v := range visited {
		visitedSet[v] = true
	}

	var overrideLog []string

	applyOne := func(name string) {
		switch name {
		case "i":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].Device = device
			}
			overrideLog = append(overrideLog, "device="+device)

		case "t":
			st := "afpacket"
			switch strings.ToLower(captureType) {
			case "pcap":
				st = "pcap"
			case "afpacket", "af_packet":
				st = "afpacket"
			}
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].SocketType = st
			}
			overrideLog = append(overrideLog, "socket_type="+st)

		case "s":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].SnapLen = snaplen
			}

		case "b":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].BufferSizeMB = bufferSizeMB
			}

		case "promisc":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].Promisc = promisc
			}

		case "pi":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].PromiscInterfaces = parseCSV(promiscIfaces)
			}

		case "bpf":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].BPFFilter = bpfFilter
			}
			overrideLog = append(overrideLog, "bpf_filter="+bpfFilter)

		case "m":
			modes := parseCaptureMode(captureMode)
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].CaptureMode = modes
			}
			overrideLog = append(overrideLog, "capture_mode="+captureMode)

		case "vlan":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].Vlan = withVlan
			}
			if withVlan {
				overrideLog = append(overrideLog, "vlan=true")
			}

		case "erspan":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].Erspan = withErspan
			}
			if withErspan {
				overrideLog = append(overrideLog, "erspan=true")
			}

		case "pr":
			minPort, maxPort, err := parsePortRange(portRange)
			if err != nil {
				log.Warn().Err(err).Str("range", portRange).Msg("Invalid -pr port range override, ignored")
				return
			}
			modes := make([]string, 0)
			for _, s := range cfg.SocketSettings {
				modes = s.CaptureMode
				break
			}
			cfg.ProtocolSettings = buildProtocolSettings(modes, minPort, maxPort)
			overrideLog = append(overrideLog, "port_range="+portRange)

		case "hs":
			servers := strings.Split(hepServer, ",")
			var newTransports []config.TransportSettings
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
				newTransports = append(newTransports, config.TransportSettings{
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
			if len(newTransports) > 0 {
				cfg.TransportSettings = newTransports
				overrideLog = append(overrideLog, "hep_server="+hepServer)
			}

		case "nt":
			applyTransportRuntimeOverrides(cfg)
			appendOverrideLogKV(&overrideLog, "network_type", networkType)

		case "skipverify":
			applyTransportRuntimeOverrides(cfg)
			appendOverrideLogKV(&overrideLog, "skipverify", strconv.FormatBool(skipVerify))

		case "keepalive":
			applyTransportRuntimeOverrides(cfg)
			appendOverrideLogKV(&overrideLog, "keepalive", strconv.FormatUint(uint64(keepAlive), 10))

		case "tcpsendretries":
			applyTransportRuntimeOverrides(cfg)
			appendOverrideLogKV(&overrideLog, "tcpsendretries", strconv.Itoa(tcpSendRetries))

		case "hin":
			applyCollectorAddrOverride(cfg)
			appendOverrideLogKV(&overrideLog, "collector_addr", collectorAddr)

		case "l":
			cfg.LogSettings.Level = logLevel
			overrideLog = append(overrideLog, "log_level="+logLevel)

		case "e":
			cfg.LogSettings.Stdout = logStdout
			appendOverrideLogKV(&overrideLog, "log_stderr", strconv.FormatBool(logStderr))

		case "S":
			cfg.LogSettings.Stdout = logStdout
			appendOverrideLogKV(&overrideLog, "log_stdout", strconv.FormatBool(logStdout))

		case "log-format":
			cfg.LogSettings.Json = logJSON
			appendOverrideLogKV(&overrideLog, "log_format", logFormat)

		case "hi":
			cfg.SystemSettings.NodeID = uint32(hepNodeID)

		case "hn":
			cfg.SystemSettings.NodeName = hepNodeName

		case "hp":
			cfg.SystemSettings.NodePW = hepNodePW

		case "fg":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].FanoutID = uint16(fanoutID)
			}

		case "fw":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].FanoutWorkers = fanoutWorkers
			}

		case "rf":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].PcapFile = readFile
			}

		case "tcpassembly":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].TcpReasm = tcpAssembly
			}

		case "sipassembly":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].SIPReasm = sipAssembly
			}

		case "ipfragment":
			for i := range cfg.SocketSettings {
				cfg.SocketSettings[i].IpFragment = ipFragment
			}

		case "dd":
			cfg.SipSettings.Deduplicate = dedup
			cfg.HepSettings.Deduplicate = dedup

		case "dim":
			cfg.SipSettings.DiscardMethods = parseCSV(discardMethods)

		case "diip":
			cfg.SipSettings.DiscardIPs = parseCSV(discardIPs)

		case "disip":
			cfg.SipSettings.DiscardSrcIP = parseCSV(discardSrcIPs)

		case "didip":
			cfg.SipSettings.DiscardDstIP = parseCSV(discardDstIPs)

		case "fi":
			cfg.FilterInclude = parseCSV(filterInclude)

		case "di":
			cfg.FilterExclude = parseCSV(filterExclude)

		case "d":
			cfg.DebugSelectors = parseCSV(debugSelectors)

		case "log-payload":
			cfg.LogSettings.LogPayload = logPayload

		case "disable-defrag":
			cfg.DebugSettings.DisableIPDefrag = disableDefrag

		case "disable-tcp-reasm":
			cfg.DebugSettings.DisableTcpReassembly = disableTcpReasm

		case "wf":
			cfg.PcapSettings.WriteFile = writeFile

		case "rt":
			cfg.PcapSettings.RotateMinutes = rotationTime

		case "zf":
			cfg.PcapSettings.Compress = compressPcap

		case "rs":
			cfg.PcapSettings.MaxSpeed = pcapMaxSpeed

		case "lp":
			cfg.PcapSettings.LoopCount = pcapLoopCount

		case "eof-exit":
			cfg.PcapSettings.EOFExit = pcapEOFExit

		case "prometheus":
			cfg.PrometheusSettings.Active = prometheusAddr != ""
			if prometheusAddr != "" {
				full := prometheusAddr
				if strings.HasPrefix(prometheusAddr, ":") {
					full = "0.0.0.0" + prometheusAddr
				}
				hostPort := strings.SplitN(full, ":", 2)
				cfg.PrometheusSettings.Host = hostPort[0]
				if len(hostPort) == 2 {
					if p, err := strconv.Atoi(hostPort[1]); err == nil {
						cfg.PrometheusSettings.Port = p
					}
				}
			}
			appendOverrideLogKV(&overrideLog, "prometheus_addr", prometheusAddr)

		case "api":
			cfg.ApiSettings.Active = apiAddr != ""
			if apiAddr != "" {
				full := apiAddr
				if strings.HasPrefix(apiAddr, ":") {
					full = "0.0.0.0" + apiAddr
				}
				hostPort := strings.SplitN(full, ":", 2)
				cfg.ApiSettings.Host = hostPort[0]
				if len(hostPort) == 2 {
					if p, err := strconv.Atoi(hostPort[1]); err == nil {
						cfg.ApiSettings.Port = p
					}
				}
				if cfg.ApiSettings.Port == 0 {
					cfg.ApiSettings.Port = 9060
				}
			}
			appendOverrideLogKV(&overrideLog, "api_addr", apiAddr)

		case "api-user":
			cfg.ApiSettings.Username = apiUser

		case "api-pass":
			cfg.ApiSettings.Password = apiPass

		case "api-tls":
			cfg.ApiSettings.TLS = apiTLS
			appendOverrideLogKV(&overrideLog, "api_tls", strconv.FormatBool(apiTLS))

		case "api-cert":
			cfg.ApiSettings.CertFile = apiCertFile

		case "api-key":
			cfg.ApiSettings.KeyFile = apiKeyFile

		case "script-file":
			cfg.ScriptSettings.File = scriptFile
			cfg.ScriptSettings.Active = scriptFile != ""
			appendOverrideLogKV(&overrideLog, "script_file", scriptFile)

		case "script-hep-filter":
			cfg.ScriptSettings.HEPFilter = scriptFilter

		case "hep-buffer-activate":
			cfg.BufferSettings.Enable = bufferEnable
			appendOverrideLogKV(&overrideLog, "buffer_enable", strconv.FormatBool(bufferEnable))

		case "hep-buffer-file":
			cfg.BufferSettings.File = bufferFile

		case "hep-buffer-max-size":
			cfg.BufferSettings.MaxSizeBytes = parseSize(bufferMaxSize)

		case "hep-buffer-debug":
			cfg.BufferSettings.Debug = bufferDebug

		case "collectonlysip":
			cfg.HepSettings.CollectOnlySIP = collectOnlySIP
			appendOverrideLogKV(&overrideLog, "collect_only_sip", strconv.FormatBool(collectOnlySIP))

		case "replacetoken":
			cfg.HepSettings.ReplaceToken = replaceToken
			appendOverrideLogKV(&overrideLog, "replace_token", strconv.FormatBool(replaceToken))
		}
	}

	applied := make(map[string]bool, len(visitedSet))
	for _, name := range visited {
		if visitedSet[name] && !applied[name] {
			applyOne(name)
			applied[name] = true
		}
	}

	if len(overrideLog) > 0 {
		log.Info().Strs("overrides", overrideLog).Msg("CLI flags override config file settings")
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
