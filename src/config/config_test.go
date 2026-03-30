package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	cfg := &Config{}
	cfg.TransportSettings = []TransportSettings{
		{
			Name:      "t1",
			Active:    true,
			Host:      "127.0.0.1",
			Port:      9060,
			Transport: "udp",
		},
	}
	cfg.ProtocolSettings = []ProtocolSettings{
		{Name: "SIP", MinPort: 5060, MaxPort: 5090, Protocol: []string{"udp"}},
	}
	cfg.BufferSettings.File = "tmp/buffer.dump"
	cfg.PrometheusSettings.Active = true
	cfg.ApiSettings.Active = true
	cfg.ApiSettings.Host = "127.0.0.1"
	cfg.ApiSettings.Port = 9096

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestValidateConfigRejectsInvalidPort(t *testing.T) {
	cfg := &Config{}
	cfg.TransportSettings = []TransportSettings{
		{
			Name:      "bad",
			Active:    true,
			Host:      "127.0.0.1",
			Port:      70000,
			Transport: "tcp",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid transport port")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test_config.json")
	content := `{
  "transport": [
    {"name":"t1","active":true,"protocol":"HEPv3","host":"127.0.0.1","transport":"udp","port":9060}
  ],
  "protocol": [
    {"name":"SIP","min_port":5060,"max_port":5090,"protocol":["udp","tcp"]}
  ],
  "prometheus_settings": {"active": true},
  "api_settings": {"active": true, "host":"127.0.0.1","port":9096}
}`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if cfg == nil {
		t.Fatal("loaded config is nil")
	}
	if len(cfg.TransportSettings) != 1 {
		t.Fatalf("unexpected transport settings count: %d", len(cfg.TransportSettings))
	}
}
