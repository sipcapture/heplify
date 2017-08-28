package config

import (
	"github.com/negbie/heplify/logp"
)

var Cfg Config

type Config struct {
	Iface      *InterfacesConfig
	IfaceAddrs map[string]bool
	Logging    *logp.Logging
	DoHep      bool
	HepServer  string
}

type InterfacesConfig struct {
	Device       string
	Type         string
	File         string
	WithVlans    bool
	BpfFilter    string
	Snaplen      int
	BufferSizeMb int
	TopSpeed     bool
	Dumpfile     string
	OneAtATime   bool
	Loop         int
}
