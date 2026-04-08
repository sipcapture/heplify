package main

import (
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
