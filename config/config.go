package config

import (
	"github.com/negbie/heplify/logp"
)

var Cfg Config

type Config struct {
	Iface          *InterfacesConfig
	Logging        *logp.Logging
	Bench          bool
	Mode           string
	Dedup          bool
	Filter         string
	Discard        string
	Gzip           bool
	HepServer      string
	HepNodeID      uint
	NsqdTCPAddress string
	NsqdTopic      string
}

type InterfacesConfig struct {
	Device       string `config:"device"`
	Type         string `config:"type"`
	ReadFile     string `config:"read_file"`
	WriteFile    string `config:"write_file"`
	RotationTime int    `config:"rotation_time"`
	PortRange    string `config:"port_range"`
	Snaplen      int    `config:"snaplen"`
	BufferSizeMb int    `config:"buffer_size_mb"`
	ReadSpeed    bool   `config:"top_speed"`
	OneAtATime   bool   `config:"one_at_a_time"`
	Loop         int    `config:"loop"`
}
