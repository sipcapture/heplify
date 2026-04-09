package main

import (
	"reflect"
	"testing"

	"github.com/sipcapture/heplify/src/config"
)

// baseConfig returns a minimal config that simulates a default config file
// loaded from /etc/heplify/heplify.json (interface=any, no ERSPAN).
func baseConfig() *config.Config {
	return &config.Config{
		SocketSettings: []config.SocketSettings{
			{
				Name:       "capture",
				Active:     true,
				SocketType: "afpacket",
				Device:     "any",
				Erspan:     false,
				Vlan:       false,
			},
		},
		TransportSettings: []config.TransportSettings{
			{Name: "default", Active: true, Protocol: "HEPv3", Host: "127.0.0.1", Port: 9060, Transport: "udp"},
		},
		LogSettings: config.LogSettings{Level: "info"},
	}
}

func setCommonCLIValues() {
	device = "ens32"
	captureType = "afpacket"
	snaplen = 1200
	bufferSizeMB = 64
	promisc = true
	promiscIfaces = "ens32"
	bpfFilter = ""
	portRange = "5060-5090"
	captureMode = "SIPRTCP"
	withVlan = false
	withErspan = true
	hepServer = "127.0.0.1:9060"
	networkType = "udp"
	skipVerify = false
	keepAlive = 5
	tcpSendRetries = 0
	collectorAddr = "udp:0.0.0.0:9062"
	logLevel = "debug"
	logFormat = "json"
	logJSON = true
	logStdout = true
	logStderr = false
	prometheusAddr = ":9096"
	apiAddr = ":9061"
	apiUser = "admin"
	apiPass = "secret"
	apiTLS = true
	apiCertFile = "/tmp/cert.pem"
	apiKeyFile = "/tmp/key.pem"
	scriptFile = "/tmp/script.lua"
	scriptFilter = "1,5,100"
	bufferEnable = true
	bufferFile = "/tmp/hep-buffer.dump"
	bufferMaxSize = "12MB"
	bufferDebug = true
	collectOnlySIP = true
	replaceToken = true
	hepNodeID = 3003
	hepNodeName = "node-a"
	hepNodePW = "pw-a"
	readFile = ""
	writeFile = "/tmp/pcap"
	rotationTime = 30
	compressPcap = true
	pcapMaxSpeed = false
	pcapLoopCount = 3
	pcapEOFExit = true
	dedup = true
	discardMethods = "OPTIONS,NOTIFY"
	discardIPs = "10.0.0.10"
	discardSrcIPs = "10.0.0.11"
	discardDstIPs = "10.0.0.12"
	filterInclude = "INVITE"
	filterExclude = "OPTIONS"
	debugSelectors = "layer,payload"
	fanoutID = 12
	fanoutWorkers = 3
	tcpAssembly = true
	sipAssembly = true
	ipFragment = true
	logPayload = true
	disableDefrag = true
	disableTcpReasm = true
}

// TestApplyExplicitCLIOverrides_DefaultsDoNotOverride ensures that flags absent
// from the visited slice do NOT overwrite config file settings. This is the key
// invariant: a config file's "device: eth0" / "erspan: true" must survive
// unchanged if the user does not pass -i / -erspan on the command line.
func TestApplyExplicitCLIOverrides_DefaultsDoNotOverride(t *testing.T) {
	cfg := baseConfig()
	cfg.SocketSettings[0].Device = "eth0"
	cfg.SocketSettings[0].Erspan = true

	// No flags explicitly set — visited list is empty.
	applyExplicitCLIOverridesWithVisited(cfg, nil)

	for _, s := range cfg.SocketSettings {
		if s.Device != "eth0" {
			t.Errorf("unset -i flag must not override config: expected eth0, got %q", s.Device)
		}
		if !s.Erspan {
			t.Errorf("unset -erspan flag must not override config: expected erspan=true, got false")
		}
	}
}

// TestApplyExplicitCLIOverrides_Interface verifies that -i <iface> overrides
// the interface from the config file (regression: issue #336).
func TestApplyExplicitCLIOverrides_Interface(t *testing.T) {
	cfg := baseConfig()
	device = "ens32"

	applyExplicitCLIOverridesWithVisited(cfg, []string{"i"})

	for _, s := range cfg.SocketSettings {
		if s.Device != "ens32" {
			t.Errorf("expected device=ens32, got %q", s.Device)
		}
	}
}

// TestApplyExplicitCLIOverrides_Erspan verifies that -erspan overrides the
// ERSPAN flag from the config file (regression: issue #336).
func TestApplyExplicitCLIOverrides_Erspan(t *testing.T) {
	cfg := baseConfig()
	withErspan = true

	applyExplicitCLIOverridesWithVisited(cfg, []string{"erspan"})

	for _, s := range cfg.SocketSettings {
		if !s.Erspan {
			t.Errorf("expected erspan=true, got false")
		}
	}
}

// TestApplyExplicitCLIOverrides_InterfaceAndErspan is the combined scenario
// reported in issue #336: docker run ... -i ens32 -erspan
func TestApplyExplicitCLIOverrides_InterfaceAndErspan(t *testing.T) {
	cfg := baseConfig()
	device = "ens32"
	withErspan = true

	applyExplicitCLIOverridesWithVisited(cfg, []string{"i", "erspan"})

	for _, s := range cfg.SocketSettings {
		if s.Device != "ens32" {
			t.Errorf("expected device=ens32, got %q", s.Device)
		}
		if !s.Erspan {
			t.Errorf("expected erspan=true, got false")
		}
	}
}

// TestApplyExplicitCLIOverrides_LogLevel verifies that -l debug overrides
// the log level from the config file.
func TestApplyExplicitCLIOverrides_LogLevel(t *testing.T) {
	cfg := baseConfig()
	cfg.LogSettings.Level = "warn"
	logLevel = "debug"

	applyExplicitCLIOverridesWithVisited(cfg, []string{"l"})

	if cfg.LogSettings.Level != "debug" {
		t.Errorf("expected log level debug, got %q", cfg.LogSettings.Level)
	}
}

// TestApplyExplicitCLIOverrides_MultiSocket verifies that when the config
// contains multiple sockets, an explicit -i flag updates all of them.
func TestApplyExplicitCLIOverrides_MultiSocket(t *testing.T) {
	cfg := baseConfig()
	cfg.SocketSettings = append(cfg.SocketSettings, config.SocketSettings{
		Name: "capture2", Active: true, Device: "any",
	})
	device = "bond0"

	applyExplicitCLIOverridesWithVisited(cfg, []string{"i"})

	for _, s := range cfg.SocketSettings {
		if s.Device != "bond0" {
			t.Errorf("expected device=bond0 for socket %q, got %q", s.Name, s.Device)
		}
	}
}

func TestApplyExplicitCLIOverrides_TransportRuntimeFlagsWithoutHS(t *testing.T) {
	cfg := baseConfig()
	cfg.TransportSettings = []config.TransportSettings{
		{Name: "a", Active: true, Transport: "tcp", SkipVerify: false, KeepAlive: 1, MaxRetries: 1},
		{Name: "b", Active: true, Transport: "tls", SkipVerify: false, KeepAlive: 2, MaxRetries: 2},
	}
	networkType = "udp"
	skipVerify = true
	keepAlive = 42
	tcpSendRetries = 9

	applyExplicitCLIOverridesWithVisited(cfg, []string{"nt", "skipverify", "keepalive", "tcpsendretries"})

	if len(cfg.TransportSettings) != 2 {
		t.Fatalf("transport list must not be replaced when -hs is absent")
	}
	for i, tr := range cfg.TransportSettings {
		if tr.Transport != "udp" {
			t.Fatalf("transport[%d] transport mismatch: %s", i, tr.Transport)
		}
		if !tr.SkipVerify {
			t.Fatalf("transport[%d] skipverify mismatch", i)
		}
		if tr.KeepAlive != 42 {
			t.Fatalf("transport[%d] keepalive mismatch: %d", i, tr.KeepAlive)
		}
		if tr.MaxRetries != 9 {
			t.Fatalf("transport[%d] retries mismatch: %d", i, tr.MaxRetries)
		}
	}
}

func TestApplyExplicitCLIOverrides_NewMappings(t *testing.T) {
	cfg := baseConfig()
	cfg.CollectorSettings.Active = false
	cfg.PrometheusSettings.Active = false
	cfg.ApiSettings.Active = false
	cfg.ScriptSettings.Active = false
	cfg.BufferSettings.Enable = false
	cfg.HepSettings.CollectOnlySIP = false
	cfg.HepSettings.ReplaceToken = false
	cfg.LogSettings.Stdout = false
	cfg.LogSettings.Json = false

	collectorAddr = "udp:0.0.0.0:9070"
	prometheusAddr = ":9097"
	apiAddr = ":9443"
	apiUser = "u1"
	apiPass = "p1"
	apiTLS = true
	apiCertFile = "/tmp/c1.pem"
	apiKeyFile = "/tmp/k1.pem"
	scriptFile = "/tmp/a.lua"
	scriptFilter = "1,5"
	bufferEnable = true
	bufferFile = "/tmp/buf.dump"
	bufferMaxSize = "16MB"
	bufferDebug = true
	collectOnlySIP = true
	replaceToken = true
	logStdout = true
	logStderr = false
	logFormat = "json"
	logJSON = true

	applyExplicitCLIOverridesWithVisited(cfg, []string{
		"hin", "prometheus", "api", "api-user", "api-pass", "api-tls", "api-cert", "api-key",
		"script-file", "script-hep-filter",
		"hep-buffer-activate", "hep-buffer-file", "hep-buffer-max-size", "hep-buffer-debug",
		"collectonlysip", "replacetoken",
		"S", "e", "log-format",
	})

	if !cfg.CollectorSettings.Active || cfg.CollectorSettings.Port != 9070 || cfg.CollectorSettings.Proto != "udp" {
		t.Fatalf("collector override failed: %+v", cfg.CollectorSettings)
	}
	if !cfg.PrometheusSettings.Active || cfg.PrometheusSettings.Port != 9097 {
		t.Fatalf("prometheus override failed: %+v", cfg.PrometheusSettings)
	}
	if !cfg.ApiSettings.Active || cfg.ApiSettings.Port != 9443 || cfg.ApiSettings.Username != "u1" || cfg.ApiSettings.Password != "p1" {
		t.Fatalf("api override failed: %+v", cfg.ApiSettings)
	}
	if !cfg.ApiSettings.TLS || cfg.ApiSettings.CertFile != "/tmp/c1.pem" || cfg.ApiSettings.KeyFile != "/tmp/k1.pem" {
		t.Fatalf("api tls override failed: %+v", cfg.ApiSettings)
	}
	if !cfg.ScriptSettings.Active || cfg.ScriptSettings.File != "/tmp/a.lua" || cfg.ScriptSettings.HEPFilter != "1,5" {
		t.Fatalf("script override failed: %+v", cfg.ScriptSettings)
	}
	if !cfg.BufferSettings.Enable || cfg.BufferSettings.File != "/tmp/buf.dump" || cfg.BufferSettings.MaxSizeBytes == 0 || !cfg.BufferSettings.Debug {
		t.Fatalf("buffer override failed: %+v", cfg.BufferSettings)
	}
	if !cfg.HepSettings.CollectOnlySIP || !cfg.HepSettings.ReplaceToken {
		t.Fatalf("hep settings override failed: %+v", cfg.HepSettings)
	}
	if !cfg.LogSettings.Stdout || !cfg.LogSettings.Json {
		t.Fatalf("log settings override failed: %+v", cfg.LogSettings)
	}
}

func TestConfigAndCLIParityForCriticalFields(t *testing.T) {
	setCommonCLIValues()

	cliCfg := buildConfigFromFlags()
	fileCfg := baseConfig()
	// Make defaults intentionally different from CLI to verify override parity.
	fileCfg.SocketSettings[0].Device = "any"
	fileCfg.SocketSettings[0].Erspan = false
	fileCfg.SocketSettings[0].CaptureMode = []string{"SIP"}
	fileCfg.TransportSettings = []config.TransportSettings{
		{Name: "legacy", Active: true, Protocol: "HEPv3", Host: "10.0.0.1", Port: 9060, Transport: "tcp"},
	}
	fileCfg.ApiSettings.Active = false
	fileCfg.PrometheusSettings.Active = false

	visited := []string{
		"i", "t", "s", "b", "promisc", "pi", "bpf", "m", "vlan", "erspan", "pr",
		"hs", "nt", "skipverify", "keepalive", "tcpsendretries", "hin",
		"l", "S", "e", "log-format", "hi", "hn", "hp", "fg", "fw", "rf",
		"tcpassembly", "sipassembly", "ipfragment", "dd", "dim", "diip", "disip", "didip",
		"fi", "di", "d", "log-payload", "disable-defrag", "disable-tcp-reasm",
		"wf", "rt", "zf", "rs", "lp", "eof-exit",
		"prometheus", "api", "api-user", "api-pass", "api-tls", "api-cert", "api-key",
		"script-file", "script-hep-filter",
		"hep-buffer-activate", "hep-buffer-file", "hep-buffer-max-size", "hep-buffer-debug",
		"collectonlysip", "replacetoken",
	}
	applyExplicitCLIOverridesWithVisited(fileCfg, visited)

	if fileCfg.SocketSettings[0].Device != cliCfg.SocketSettings[0].Device {
		t.Fatalf("device mismatch: cfg+cli=%s cli-only=%s", fileCfg.SocketSettings[0].Device, cliCfg.SocketSettings[0].Device)
	}
	if fileCfg.SocketSettings[0].Erspan != cliCfg.SocketSettings[0].Erspan {
		t.Fatalf("erspan mismatch")
	}
	if !reflect.DeepEqual(fileCfg.SocketSettings[0].CaptureMode, cliCfg.SocketSettings[0].CaptureMode) {
		t.Fatalf("capture mode mismatch: %v vs %v", fileCfg.SocketSettings[0].CaptureMode, cliCfg.SocketSettings[0].CaptureMode)
	}
	if len(fileCfg.TransportSettings) != len(cliCfg.TransportSettings) {
		t.Fatalf("transport len mismatch: %d vs %d", len(fileCfg.TransportSettings), len(cliCfg.TransportSettings))
	}
	if len(fileCfg.TransportSettings) > 0 {
		a := fileCfg.TransportSettings[0]
		b := cliCfg.TransportSettings[0]
		if a.Host != b.Host || a.Port != b.Port || a.Transport != b.Transport || a.SkipVerify != b.SkipVerify || a.KeepAlive != b.KeepAlive || a.MaxRetries != b.MaxRetries {
			t.Fatalf("transport mismatch: %+v vs %+v", a, b)
		}
	}
	if !reflect.DeepEqual(fileCfg.ProtocolSettings, cliCfg.ProtocolSettings) {
		t.Fatalf("protocol settings mismatch")
	}
	if fileCfg.ApiSettings.Active != cliCfg.ApiSettings.Active || fileCfg.ApiSettings.Port != cliCfg.ApiSettings.Port {
		t.Fatalf("api settings mismatch: %+v vs %+v", fileCfg.ApiSettings, cliCfg.ApiSettings)
	}
	if fileCfg.PrometheusSettings.Active != cliCfg.PrometheusSettings.Active || fileCfg.PrometheusSettings.Port != cliCfg.PrometheusSettings.Port {
		t.Fatalf("prometheus settings mismatch: %+v vs %+v", fileCfg.PrometheusSettings, cliCfg.PrometheusSettings)
	}
	if fileCfg.BufferSettings.Enable != cliCfg.BufferSettings.Enable || fileCfg.BufferSettings.MaxSizeBytes != cliCfg.BufferSettings.MaxSizeBytes {
		t.Fatalf("buffer settings mismatch: %+v vs %+v", fileCfg.BufferSettings, cliCfg.BufferSettings)
	}
	if fileCfg.HepSettings.CollectOnlySIP != cliCfg.HepSettings.CollectOnlySIP || fileCfg.HepSettings.ReplaceToken != cliCfg.HepSettings.ReplaceToken {
		t.Fatalf("hep settings mismatch: %+v vs %+v", fileCfg.HepSettings, cliCfg.HepSettings)
	}
}

func TestResolveConfigFilePath_FromFlag(t *testing.T) {
	t.Setenv("HEPLIFY_CONFIG", "/tmp/from-env.json")
	path, fromEnv := resolveConfigFilePath("/tmp/from-flag.json", false)
	if fromEnv {
		t.Fatalf("expected fromEnv=false when -config is provided")
	}
	if path != "/tmp/from-flag.json" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestResolveConfigFilePath_FromEnv(t *testing.T) {
	t.Setenv("HEPLIFY_CONFIG", "/tmp/from-env.json")
	path, fromEnv := resolveConfigFilePath("", false)
	if !fromEnv {
		t.Fatalf("expected fromEnv=true when using HEPLIFY_CONFIG")
	}
	if path != "/tmp/from-env.json" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestResolveConfigFilePath_NoConfigWins(t *testing.T) {
	t.Setenv("HEPLIFY_CONFIG", "/tmp/from-env.json")
	path, fromEnv := resolveConfigFilePath("/tmp/from-flag.json", true)
	if fromEnv {
		t.Fatalf("expected fromEnv=false when -no-config is set")
	}
	if path != "" {
		t.Fatalf("expected empty config path with -no-config, got: %s", path)
	}
}
