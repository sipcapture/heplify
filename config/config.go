package config

import (
	"github.com/negbie/heplify/logp"
)

var Cfg Config

type Config struct {
	Iface     *InterfacesConfig
	Logging   *logp.Logging
	Mode      string
	Dedup     bool
	Filter    string
	Discard   string
	HepServer string
}

type InterfacesConfig struct {
	Device       string `config:"device"`
	Type         string `config:"type"`
	ReadFile     string `config:"read_file"`
	WriteFile    string `config:"write_file"`
	Snaplen      int    `config:"snaplen"`
	BufferSizeMb int    `config:"buffer_size_mb"`
	ReadSpeed    bool   `config:"top_speed"`
	OneAtATime   bool   `config:"one_at_a_time"`
	Loop         int    `config:"loop"`
}
