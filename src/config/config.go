package config

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Config represents the top-level configuration structure
type Config struct {
	SocketSettings    []SocketSettings    `json:"socket" mapstructure:"socket"`
	TransportSettings []TransportSettings `json:"transport" mapstructure:"transport"`
	SubscribeSettings SubscribeSettings   `json:"subscribe_settings" mapstructure:"subscribe_settings"`
	LogSettings       LogSettings         `json:"log_settings" mapstructure:"log_settings"`
	ProtocolSettings  []ProtocolSettings  `json:"protocol" mapstructure:"protocol"`

	NetworkSettings struct {
		OptionChecker     bool     `json:"option_checker" mapstructure:"option_checker"`
		TCPChecksum       bool     `json:"tcp_checksum" mapstructure:"tcp_checksum"`
		PromiscInterfaces []string `json:"promisc_interfaces" mapstructure:"promisc_interfaces"`
	} `json:"network_settings" mapstructure:"network_settings"`

	SipSettings struct {
		ParseOnlySDPActive bool     `json:"parse_only_sdp" mapstructure:"parse_only_sdp"`
		CensorMethod       []string `json:"censored_methods" mapstructure:"censored_methods"`
		DiscardMethods     []string `json:"discard_methods" mapstructure:"discard_methods"`
		DisconnectActive   bool     `json:"disconnect_active" mapstructure:"disconnect_active"`
		DiscardIPs         []string `json:"discard_ips" mapstructure:"discard_ips"`
		DiscardSrcIP       []string `json:"discard_src_ips" mapstructure:"discard_src_ips"`
		DiscardDstIP       []string `json:"discard_dst_ips" mapstructure:"discard_dst_ips"`
		AlegIDs            []string `json:"aleg_ids" mapstructure:"aleg_ids"`
		Deduplicate        bool     `json:"deduplicate" mapstructure:"deduplicate"`
		CustomHeaders      []string `json:"custom_headers" mapstructure:"custom_headers"`
		CheckSIPInterval   string   `json:"check_sip_interval" mapstructure:"check_sip_interval"`
		NumWorkers         int      `json:"num_workers" mapstructure:"num_workers"`
		EncodeHep          bool     `json:"encode_hep" mapstructure:"encode_hep"`
		Transaction        struct {
			Call        bool   `json:"call" mapstructure:"call"`
			Register    bool   `json:"register" mapstructure:"register"`
			CallTimeout string `json:"call_timeout" mapstructure:"call_timeout"`
		} `json:"transaction" mapstructure:"transaction"`
		ForceALegID   bool `json:"force_aleg_id" mapstructure:"force_aleg_id"`
		DialogTimeout int  `json:"dialog_timeout" mapstructure:"dialog_timeout"`
	} `json:"sip_settings" mapstructure:"sip_settings"`

	InterceptionSettings struct {
		Active           bool   `json:"active" mapstructure:"active"`
		Interval         string `json:"interval" mapstructure:"interval"`
		StatsInterval    string `json:"stats_interval" mapstructure:"stats_interval"`
		WorkerCount      int    `json:"worker_count" mapstructure:"worker_count"`
		MaxInterceptions int    `json:"max_interceptions" mapstructure:"max_interceptions"`
	} `json:"interception_settings" mapstructure:"interception_settings"`

	HepSettings struct {
		HepV2Active  bool `json:"hepv2_active" mapstructure:"hepv2_active"`
		HepV3Active  bool `json:"hepv3_active" mapstructure:"hepv3_active"`
		Deduplicate  bool `json:"deduplicate" mapstructure:"deduplicate"`
		ReplaceToken bool `json:"replace_token" mapstructure:"replace_token"`
		ReplaceCID   bool `json:"replace_cid" mapstructure:"replace_cid"`
		// CollectOnlySIP: in collector mode, accept only HEP ProtoType=1 (SIP)
		CollectOnlySIP bool `json:"collect_only_sip" mapstructure:"collect_only_sip"`
	} `json:"hep_settings" mapstructure:"hep_settings"`

	SystemSettings struct {
		HostName         string `json:"hostname" mapstructure:"hostname"`
		NodeName         string `json:"node_name" mapstructure:"node_name"`
		NodeID           uint32 `json:"node_id" mapstructure:"node_id"`
		NodePW           string `json:"node_pw" mapstructure:"node_pw"`
		Url              string `json:"url" mapstructure:"url"`
		Uuid             string `json:"uuid" mapstructure:"uuid"`
		UuidOnStart      bool   `json:"uuid_on_start" mapstructure:"uuid_on_start"`
		Daemon           bool   `json:"daemon" mapstructure:"daemon"`
		PidFile          string `json:"pid_file" mapstructure:"pid_file"`
		FragFullSearch   bool   `json:"fragment_full_search" mapstructure:"fragment_full_search"`
		IPDefragOriginal bool   `json:"ip_defrag_original" mapstructure:"ip_defrag_original"`
		TCPReasmV2       bool   `json:"tcp_reasm_v2" mapstructure:"tcp_reasm_v2"`
		ValidateSnaplen  bool   `json:"validate_snaplen" mapstructure:"validate_snaplen"`
		Tcpreasm         struct {
			Debug           bool   `json:"debug" mapstructure:"debug"`
			CleanTimeout    string `json:"clean_timeout" mapstructure:"clean_timeout"`
			FragmentTimeout string `json:"fragment_timeout" mapstructure:"fragment_timeout"`
		} `json:"tcpreasm" mapstructure:"tcpreasm"`

		Queues struct {
			RTPPacketQueueSize     int `json:"rtp_packet_queue_size" mapstructure:"rtp_packet_queue_size"`
			RTCPPacketQueueSize    int `json:"rtcp_packet_queue_size" mapstructure:"rtcp_packet_queue_size"`
			DisconnectQueueSize    int `json:"disconnect_queue_size" mapstructure:"disconnect_queue_size"`
			SIPProcessQueueSize    int `json:"sip_process_queue_size" mapstructure:"sip_process_queue_size"`
			InterceptionQueueSize  int `json:"interception_queue_size" mapstructure:"interception_queue_size"`
			HEPQueueSize           int `json:"hep_queue_size" mapstructure:"hep_queue_size"`
			PublishPacketQueueSize int `json:"publish_packet_queue_size" mapstructure:"publish_packet_queue_size"`
			IPDefragmenter         int `json:"ip_defragmenter" mapstructure:"ip_defragmenter"`
			TCPReassembler         int `json:"tcp_reassembler" mapstructure:"tcp_reassembler"`
		} `json:"queue" mapstructure:"queue"`

		Pprof struct {
			Active bool   `json:"active" mapstructure:"active"`
			Url    string `json:"url" mapstructure:"url"`
		} `json:"pprof" mapstructure:"pprof"`
	} `json:"system_settings" mapstructure:"system_settings"`

	PrometheusSettings struct {
		Active bool   `json:"active" mapstructure:"active"`
		Host   string `json:"host" mapstructure:"host"`
		Port   int    `json:"port" mapstructure:"port"`
	} `json:"prometheus_settings" mapstructure:"prometheus_settings"`

	DebugSettings struct {
		DisableRtpStats      bool `json:"disable_rtp_stats" mapstructure:"disable_rtp_stats"`
		DisableSipStats      bool `json:"disable_sip_stats" mapstructure:"disable_sip_stats"`
		DisablePublish       bool `json:"disable_publish" mapstructure:"disable_publish"`
		DisableDisconnect    bool `json:"disable_disconnect" mapstructure:"disable_disconnect"`
		DisableInterception  bool `json:"disable_interception" mapstructure:"disable_interception"`
		DisableTcpReassembly bool `json:"disable_tcp_reassembly" mapstructure:"disable_tcp_reassembly"`
		DisableIPDefrag      bool `json:"disable_ip_defrag" mapstructure:"disable_ip_defrag"`
	} `json:"debug_settings" mapstructure:"debug_settings"`

	HttpSettings struct {
		Active    bool   `json:"active" mapstructure:"active"`
		Host      string `json:"host" mapstructure:"host"`
		Port      int    `json:"port" mapstructure:"port"`
		ApiPrefix string `json:"api_prefix" mapstructure:"api_prefix"`
		Debug     bool   `json:"debug" mapstructure:"debug"`
	} `json:"http_settings" mapstructure:"http_settings"`

	ScriptSettings ScriptSettings `json:"script_settings" mapstructure:"script_settings"`

	// FilterInclude: pass packet only if payload contains ALL these strings (-fi)
	FilterInclude []string `json:"filter_include" mapstructure:"filter_include"`
	// FilterExclude: drop packet if payload contains ANY of these strings (-di)
	FilterExclude []string `json:"filter_exclude" mapstructure:"filter_exclude"`
	// DebugSelectors: fine-grained debug logging (defrag, layer, payload, rtp, rtcp, sdp)
	DebugSelectors []string `json:"debug_selectors" mapstructure:"debug_selectors"`

	PcapSettings struct {
		WriteEnable   bool   `json:"write_enable" mapstructure:"write_enable"`
		WritePath     string `json:"write_path" mapstructure:"write_path"`
		RotateMinutes int    `json:"rotate_minutes" mapstructure:"rotate_minutes"`
		Compress      bool   `json:"compress" mapstructure:"compress"`
		// MaxSpeed: replay pcap at max speed, ignoring timestamps (-rs)
		MaxSpeed bool `json:"max_speed" mapstructure:"max_speed"`
		// LoopCount: number of times to replay pcap file, 0=infinite (-lp)
		LoopCount int `json:"loop_count" mapstructure:"loop_count"`
		// EOFExit: exit when pcap replay reaches EOF (-eof-exit)
		EOFExit bool `json:"eof_exit" mapstructure:"eof_exit"`
	} `json:"pcap_settings" mapstructure:"pcap_settings"`

	BufferSettings struct {
		Enable       bool   `json:"enable" mapstructure:"enable"`
		File         string `json:"file" mapstructure:"file"`         // default: "hep-buffer.dump"
		MaxSizeBytes int64  `json:"max_size" mapstructure:"max_size"` // default: 100MB
		Debug        bool   `json:"debug" mapstructure:"debug"`
	} `json:"buffer_settings" mapstructure:"buffer_settings"`
}

type SocketSettings struct {
	Name                 string   `json:"name" mapstructure:"name"`
	Active               bool     `json:"active" mapstructure:"active"`
	SocketType           string   `json:"socket_type" mapstructure:"socket_type"` // "pcap" or "afpacket"
	SequentialProcessing bool     `json:"sequential_processing" mapstructure:"sequential_processing"`
	CollectorHost        string   `json:"collector_host" mapstructure:"collector_host"`
	CollectorPort        int      `json:"collector_port" mapstructure:"collector_port"`
	CollectorProto       string   `json:"collector_proto" mapstructure:"collector_proto"`
	Device               string   `json:"device" mapstructure:"device"`
	Promisc              bool     `json:"promisc" mapstructure:"promisc"`
	TcpReasm             bool     `json:"tcp_reasm" mapstructure:"tcp_reasm"`
	IpFragment           bool     `json:"ipfragments" mapstructure:"ipfragments"`
	Vlan                 bool     `json:"vlan" mapstructure:"vlan"`
	Erspan               bool     `json:"erspan" mapstructure:"erspan"`
	Vxlan                bool     `json:"vxlan" mapstructure:"vxlan"`
	PcapFile             string   `json:"pcap_file" mapstructure:"pcap_file"`
	SnapLen              int      `json:"snap_len" mapstructure:"snap_len"`
	CaptureMode          []string `json:"capture_mode" mapstructure:"capture_mode"`
	FanoutID             uint16   `json:"fanout_id" mapstructure:"fanout_id"`
	FanoutWorkers        int      `json:"fanout_workers" mapstructure:"fanout_workers"` // Number of AF_PACKET workers
	BufferSizeMB         int      `json:"buffer_size_mb" mapstructure:"buffer_size_mb"` // AF_PACKET buffer size in MB
	LimitCPU             int      `json:"cpu_limit" mapstructure:"cpu_limit"`
	BPFFilter            string   `json:"bpf_filter" mapstructure:"bpf_filter"` // Custom BPF filter
	SIPReasm             bool     `json:"sip_reasm" mapstructure:"sip_reasm"`
}

type TransportSettings struct {
	Name       string `json:"name" mapstructure:"name"`
	Active     bool   `json:"active" mapstructure:"active"`
	Protocol   string `json:"protocol" mapstructure:"protocol"`
	Host       string `json:"host" mapstructure:"host"`
	Transport  string `json:"transport" mapstructure:"transport"`
	Port       int    `json:"port" mapstructure:"port"`
	Password   string `json:"password" mapstructure:"password"`
	PayloadZip bool   `json:"payload_zip" mapstructure:"payload_zip"`
	SkipVerify bool   `json:"skip_verify" mapstructure:"skip_verify"`
	KeepAlive  int    `json:"keepalive" mapstructure:"keepalive"`     // TCP keepalive in seconds, 0 = disabled
	MaxRetries int    `json:"max_retries" mapstructure:"max_retries"` // max reconnect attempts, 0 = unlimited
	// Arrow Flight fields (used when transport = "grpc-flight")
	TLSEnabled      bool   `json:"tls_enabled"       mapstructure:"tls_enabled"`
	StreamName      string `json:"stream_name"       mapstructure:"stream_name"`
	BatchSize       int    `json:"batch_size"        mapstructure:"batch_size"`
	FlushIntervalMs int    `json:"flush_interval_ms" mapstructure:"flush_interval_ms"`
}

type ProtocolSettings struct {
	Name        string   `json:"name" mapstructure:"name"`
	Filter      string   `json:"filter" mapstructure:"filter"`
	MinPort     uint16   `json:"min_port" mapstructure:"min_port"`
	MaxPort     uint16   `json:"max_port" mapstructure:"max_port"`
	Protocol    []string `json:"protocol" mapstructure:"protocol"`
	Description string   `json:"description" mapstructure:"description"`
}

type LogSettings struct {
	Active     bool   `json:"active" mapstructure:"active"`
	Timestamp  bool   `json:"timestamp" mapstructure:"timestamp"`
	Path       string `json:"path" mapstructure:"path"`
	Level      string `json:"level" mapstructure:"level"`
	Name       string `json:"name" mapstructure:"name"`
	Stdout     bool   `json:"stdout" mapstructure:"stdout"`
	Json       bool   `json:"json" mapstructure:"json"`
	SysLog     bool   `json:"syslog" mapstructure:"syslog"`
	LogPayload bool   `json:"log_payload" mapstructure:"log_payload"` // print SIP payload as plain text in debug logs
}

type SubscribeSettings struct {
	Active bool `json:"active" mapstructure:"active"`
}

type ScriptSettings struct {
	Active    bool   `json:"active" mapstructure:"active"`
	File      string `json:"file" mapstructure:"file"`
	HEPFilter string `json:"hep_filter" mapstructure:"hep_filter"`
}

func (c *Config) Validate() error {
	for i, t := range c.TransportSettings {
		if t.Active {
			if t.Port < 1 || t.Port > 65535 {
				return fmt.Errorf("transport[%d] has invalid port: %d", i, t.Port)
			}
			if t.Host == "" {
				return fmt.Errorf("transport[%d] has empty host", i)
			}
			switch strings.ToLower(t.Transport) {
			case "udp", "tcp", "tls", "grpc-flight", "":
			default:
				return fmt.Errorf("transport[%d] has unsupported transport: %s", i, t.Transport)
			}
		}
	}

	for i, p := range c.ProtocolSettings {
		if p.MinPort == 0 || p.MinPort > p.MaxPort {
			return fmt.Errorf("protocol[%d] has invalid port range: %d-%d", i, p.MinPort, p.MaxPort)
		}
	}

	for i, s := range c.SocketSettings {
		if s.Active {
			if s.SnapLen < 0 {
				return fmt.Errorf("socket[%d] has invalid snap_len: %d", i, s.SnapLen)
			}
			if s.CollectorPort < 0 || s.CollectorPort > 65535 {
				return fmt.Errorf("socket[%d] has invalid collector_port: %d", i, s.CollectorPort)
			}
		}
	}

	if c.BufferSettings.MaxSizeBytes < 0 {
		return fmt.Errorf("buffer_settings.max_size must be >= 0")
	}
	if c.BufferSettings.File != "" {
		clean := filepath.Clean(c.BufferSettings.File)
		if strings.Contains(clean, "..") {
			return fmt.Errorf("buffer_settings.file contains invalid traversal path")
		}
	}

	if c.PrometheusSettings.Active {
		if c.PrometheusSettings.Port < 1 || c.PrometheusSettings.Port > 65535 {
			return fmt.Errorf("prometheus_settings.port has invalid value: %d", c.PrometheusSettings.Port)
		}
		if c.PrometheusSettings.Host != "" && c.PrometheusSettings.Host != "0.0.0.0" {
			if ip := net.ParseIP(c.PrometheusSettings.Host); ip == nil && c.PrometheusSettings.Host != "localhost" {
				return fmt.Errorf("prometheus_settings.host is not a valid host/ip: %s", c.PrometheusSettings.Host)
			}
		}
	}

	return nil
}
