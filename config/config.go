package config

import (
	"github.com/negbie/heplify/logp"
)

var Cfg Config

type Config struct {
	Iface     *InterfacesConfig
	Logging   *logp.Logging
	Reasm     bool
	HepDedup  bool
	HepFilter string
	HepServer string
}

type InterfacesConfig struct {
	Device       string `config:"device"`
	Type         string `config:"type"`
	ReadFile     string `config:"file"`
	BpfFilter    string `config:"bpf_filter"`
	Snaplen      int    `config:"snaplen"`
	BufferSizeMb int    `config:"buffer_size_mb"`
	TopSpeed     bool
	WriteFile    string
	OneAtATime   bool
	Loop         int
}
