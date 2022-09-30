package config

import (
	"github.com/negbie/logp"
)

var Cfg Config

type Config struct {
	Iface          *InterfacesConfig
	Logging        *logp.Logging
	Mode           string
	Dedup          bool
	Filter         string
	Discard        string
	DiscardMethod  string
	DiscardIP      string
	DiscardSrcIP   string
	DiscardDstIP   string
	Zip            bool
	HepCollector   string
	CollectOnlySip bool
	HepServer      string
	HepNodePW      string
	HepNodeID      uint
	HepNodeName    string
	Network        string
	Protobuf       bool
	Reassembly     bool
	SendRetries    uint
	Version        bool
}

type InterfacesConfig struct {
	Device       string `config:"device"`
	Type         string `config:"type"`
	ReadFile     string `config:"read_file"`
	WriteFile    string `config:"write_file"`
	RotationTime int    `config:"rotation_time"`
	PortRange    string `config:"port_range"`
	WithVlan     bool   `config:"with_vlan"`
	WithErspan   bool   `config:"with_erspan"`
	Snaplen      int    `config:"snaplen"`
	BufferSizeMb int    `config:"buffer_size_mb"`
	ReadSpeed    bool   `config:"top_speed"`
	OneAtATime   bool   `config:"one_at_a_time"`
	Loop         int    `config:"loop"`
	FanoutID     uint   `config:"fanout_id"`
	FanoutWorker int    `config:"fanout_worker"`
	CustomBPF    string `config:"custom_bpf"`
}
