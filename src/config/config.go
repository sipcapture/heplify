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
	LogSettings       LogSettings         `json:"log_settings" mapstructure:"log_settings"`
	ProtocolSettings  []ProtocolSettings  `json:"protocol" mapstructure:"protocol"`

	SipSettings struct {
		DiscardMethods []string `json:"discard_methods" mapstructure:"discard_methods"`
		DiscardIPs     []string `json:"discard_ips" mapstructure:"discard_ips"`
		DiscardSrcIP   []string `json:"discard_src_ips" mapstructure:"discard_src_ips"`
		DiscardDstIP   []string `json:"discard_dst_ips" mapstructure:"discard_dst_ips"`
		Deduplicate    bool     `json:"deduplicate" mapstructure:"deduplicate"`
	} `json:"sip_settings" mapstructure:"sip_settings"`

	HepSettings struct {
		ReplaceToken   bool `json:"replace_token" mapstructure:"replace_token"`
		Deduplicate    bool `json:"deduplicate" mapstructure:"deduplicate"`
		CollectOnlySIP bool `json:"collect_only_sip" mapstructure:"collect_only_sip"`
	} `json:"hep_settings" mapstructure:"hep_settings"`

	RtcpSettings struct {
		Active bool `json:"active" mapstructure:"active"`
	} `json:"rtcp_settings" mapstructure:"rtcp_settings"`

	SystemSettings struct {
		NodeName string `json:"node_name" mapstructure:"node_name"`
		NodeID   uint32 `json:"node_id" mapstructure:"node_id"`
		NodePW   string `json:"node_pw" mapstructure:"node_pw"`
	} `json:"system_settings" mapstructure:"system_settings"`

	PrometheusSettings struct {
		Active bool   `json:"active" mapstructure:"active"`
		Host   string `json:"host" mapstructure:"host"`
		Port   int    `json:"port" mapstructure:"port"`
	} `json:"prometheus_settings" mapstructure:"prometheus_settings"`

	DebugSettings struct {
		DisableTcpReassembly bool `json:"disable_tcp_reassembly" mapstructure:"disable_tcp_reassembly"`
		DisableIPDefrag      bool `json:"disable_ip_defrag" mapstructure:"disable_ip_defrag"`
	} `json:"debug_settings" mapstructure:"debug_settings"`

	ScriptSettings ScriptSettings `json:"script_settings" mapstructure:"script_settings"`

	// DebugSelectors: fine-grained debug logging (defrag, layer, payload, rtp, rtcp, sdp)
	DebugSelectors []string `json:"debug_selectors" mapstructure:"debug_selectors"`
	// FilterInclude: pass packet only if payload contains ALL these strings (-fi)
	FilterInclude []string `json:"filter_include" mapstructure:"filter_include"`
	// FilterExclude: drop packet if payload contains ANY of these strings (-di)
	FilterExclude []string `json:"filter_exclude" mapstructure:"filter_exclude"`

	PcapSettings struct {
		// WriteFile: output directory for captured pcap files (-wf)
		WriteFile string `json:"write_file" mapstructure:"write_file"`
		// RotateMinutes: pcap rotation interval in minutes (-rt)
		RotateMinutes int `json:"rotate_minutes" mapstructure:"rotate_minutes"`
		// Compress: gzip-compress rotated pcap files (-zf)
		Compress bool `json:"compress" mapstructure:"compress"`
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
	Level      string `json:"level" mapstructure:"level"`
	Stdout     bool   `json:"stdout" mapstructure:"stdout"`
	Json       bool   `json:"json" mapstructure:"json"`
	LogPayload bool   `json:"log_payload" mapstructure:"log_payload"` // print SIP payload as plain text in debug logs
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
