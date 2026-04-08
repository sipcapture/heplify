package config

import (
	"os"
	"strings"
	"testing"
)

// TestEnvUpdaterInitialize verifies that the updater initialises and discovers
// a reasonable number of field mappings.
func TestEnvUpdaterInitialize(t *testing.T) {
	eu := NewEnvUpdater()
	if err := eu.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}
	if !eu.initialized {
		t.Fatal("updater should be marked as initialized")
	}
	count := eu.GetFieldMappingsCount()
	if count == 0 {
		t.Fatal("expected at least one field mapping")
	}
	t.Logf("total field mappings: %d", count)
	eu.PrintFieldMappings()
}

// TestEnvUpdaterScalarFields verifies that simple scalar fields in nested
// anonymous structs are correctly updated from ENV variables.
func TestEnvUpdaterScalarFields(t *testing.T) {
	os.Setenv("HEPLIFY_SYSTEM_SETTINGS_NODE_NAME", "test-node")
	os.Setenv("HEPLIFY_LOG_SETTINGS_LEVEL", "debug")
	os.Setenv("HEPLIFY_LOG_SETTINGS_STDOUT", "true")
	os.Setenv("HEPLIFY_PROMETHEUS_SETTINGS_PORT", "9099")
	defer func() {
		os.Unsetenv("HEPLIFY_SYSTEM_SETTINGS_NODE_NAME")
		os.Unsetenv("HEPLIFY_LOG_SETTINGS_LEVEL")
		os.Unsetenv("HEPLIFY_LOG_SETTINGS_STDOUT")
		os.Unsetenv("HEPLIFY_PROMETHEUS_SETTINGS_PORT")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	n, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}
	t.Logf("updated %d fields", n)

	if cfg.SystemSettings.NodeName != "test-node" {
		t.Errorf("NodeName: got %q, want %q", cfg.SystemSettings.NodeName, "test-node")
	}
	if cfg.LogSettings.Level != "debug" {
		t.Errorf("LogSettings.Level: got %q, want %q", cfg.LogSettings.Level, "debug")
	}
	if !cfg.LogSettings.Stdout {
		t.Error("LogSettings.Stdout should be true")
	}
	if cfg.PrometheusSettings.Port != 9099 {
		t.Errorf("PrometheusSettings.Port: got %d, want 9099", cfg.PrometheusSettings.Port)
	}
}

// TestEnvUpdaterSliceStructElements verifies that elements of []TransportSettings
// and []SocketSettings can be initialised and set via ENV.
func TestEnvUpdaterSliceStructElements(t *testing.T) {
	os.Setenv("HEPLIFY_TRANSPORT__0__HOST", "192.168.1.1")
	os.Setenv("HEPLIFY_TRANSPORT__0__PORT", "9060")
	os.Setenv("HEPLIFY_TRANSPORT__0__ACTIVE", "true")
	os.Setenv("HEPLIFY_TRANSPORT__0__TRANSPORT", "tcp")
	os.Setenv("HEPLIFY_TRANSPORT__1__HOST", "10.0.0.1")
	os.Setenv("HEPLIFY_TRANSPORT__1__PORT", "9061")
	defer func() {
		os.Unsetenv("HEPLIFY_TRANSPORT__0__HOST")
		os.Unsetenv("HEPLIFY_TRANSPORT__0__PORT")
		os.Unsetenv("HEPLIFY_TRANSPORT__0__ACTIVE")
		os.Unsetenv("HEPLIFY_TRANSPORT__0__TRANSPORT")
		os.Unsetenv("HEPLIFY_TRANSPORT__1__HOST")
		os.Unsetenv("HEPLIFY_TRANSPORT__1__PORT")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	n, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}
	t.Logf("updated %d fields", n)

	if len(cfg.TransportSettings) < 2 {
		t.Fatalf("expected at least 2 TransportSettings, got %d", len(cfg.TransportSettings))
	}
	if cfg.TransportSettings[0].Host != "192.168.1.1" {
		t.Errorf("transport[0].Host: got %q, want %q", cfg.TransportSettings[0].Host, "192.168.1.1")
	}
	if cfg.TransportSettings[0].Port != 9060 {
		t.Errorf("transport[0].Port: got %d, want 9060", cfg.TransportSettings[0].Port)
	}
	if !cfg.TransportSettings[0].Active {
		t.Error("transport[0].Active should be true")
	}
	if cfg.TransportSettings[0].Transport != "tcp" {
		t.Errorf("transport[0].Transport: got %q, want %q", cfg.TransportSettings[0].Transport, "tcp")
	}
	if cfg.TransportSettings[1].Host != "10.0.0.1" {
		t.Errorf("transport[1].Host: got %q, want %q", cfg.TransportSettings[1].Host, "10.0.0.1")
	}
	if cfg.TransportSettings[1].Port != 9061 {
		t.Errorf("transport[1].Port: got %d, want 9061", cfg.TransportSettings[1].Port)
	}
}

// TestEnvUpdaterSocketSlice verifies []SocketSettings works the same way.
func TestEnvUpdaterSocketSlice(t *testing.T) {
	os.Setenv("HEPLIFY_SOCKET__0__DEVICE", "eth0")
	os.Setenv("HEPLIFY_SOCKET__0__ACTIVE", "true")
	os.Setenv("HEPLIFY_SOCKET__0__SNAP_LEN", "65535")
	defer func() {
		os.Unsetenv("HEPLIFY_SOCKET__0__DEVICE")
		os.Unsetenv("HEPLIFY_SOCKET__0__ACTIVE")
		os.Unsetenv("HEPLIFY_SOCKET__0__SNAP_LEN")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	_, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}

	if len(cfg.SocketSettings) == 0 {
		t.Fatal("expected at least one SocketSettings element")
	}
	if cfg.SocketSettings[0].Device != "eth0" {
		t.Errorf("socket[0].Device: got %q, want %q", cfg.SocketSettings[0].Device, "eth0")
	}
	if !cfg.SocketSettings[0].Active {
		t.Error("socket[0].Active should be true")
	}
	if cfg.SocketSettings[0].SnapLen != 65535 {
		t.Errorf("socket[0].SnapLen: got %d, want 65535", cfg.SocketSettings[0].SnapLen)
	}
}

// TestEnvUpdaterStringSliceField verifies that []string fields inside nested
// structs (e.g. SipSettings.DiscardMethods) can be set via indexed ENV vars.
func TestEnvUpdaterStringSliceField(t *testing.T) {
	os.Setenv("HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0", "REGISTER")
	os.Setenv("HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__1", "OPTIONS")
	os.Setenv("HEPLIFY_FILTER_INCLUDE__0", "INVITE")
	defer func() {
		os.Unsetenv("HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0")
		os.Unsetenv("HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__1")
		os.Unsetenv("HEPLIFY_FILTER_INCLUDE__0")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	_, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}

	if len(cfg.SipSettings.DiscardMethods) < 2 {
		t.Fatalf("DiscardMethods: got %d elements, want 2", len(cfg.SipSettings.DiscardMethods))
	}
	if cfg.SipSettings.DiscardMethods[0] != "REGISTER" {
		t.Errorf("DiscardMethods[0]: got %q, want REGISTER", cfg.SipSettings.DiscardMethods[0])
	}
	if cfg.SipSettings.DiscardMethods[1] != "OPTIONS" {
		t.Errorf("DiscardMethods[1]: got %q, want OPTIONS", cfg.SipSettings.DiscardMethods[1])
	}
	if len(cfg.FilterInclude) < 1 || cfg.FilterInclude[0] != "INVITE" {
		t.Errorf("FilterInclude[0]: got %v, want [INVITE]", cfg.FilterInclude)
	}
}

// TestEnvUpdaterBoolAndUint tests bool inversion and uint32 fields.
func TestEnvUpdaterBoolAndUint(t *testing.T) {
	os.Setenv("HEPLIFY_SIP_SETTINGS_DEDUPLICATE", "true")
	os.Setenv("HEPLIFY_HEP_SETTINGS_DEDUPLICATE", "true")
	os.Setenv("HEPLIFY_DEBUG_SETTINGS_DISABLE_IP_DEFRAG", "true")
	defer func() {
		os.Unsetenv("HEPLIFY_SIP_SETTINGS_DEDUPLICATE")
		os.Unsetenv("HEPLIFY_HEP_SETTINGS_DEDUPLICATE")
		os.Unsetenv("HEPLIFY_DEBUG_SETTINGS_DISABLE_IP_DEFRAG")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	_, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}

	if !cfg.SipSettings.Deduplicate {
		t.Error("SipSettings.Deduplicate should be true")
	}
	if !cfg.HepSettings.Deduplicate {
		t.Error("HepSettings.Deduplicate should be true")
	}
	if !cfg.DebugSettings.DisableIPDefrag {
		t.Error("DebugSettings.DisableIPDefrag should be true")
	}
}

// TestEnvUpdaterApiSettings tests deeply nested anonymous struct fields.
func TestEnvUpdaterApiSettings(t *testing.T) {
	os.Setenv("HEPLIFY_API_SETTINGS_PORT", "8080")
	os.Setenv("HEPLIFY_API_SETTINGS_HOST", "0.0.0.0")
	os.Setenv("HEPLIFY_API_SETTINGS_USERNAME", "admin")
	os.Setenv("HEPLIFY_API_SETTINGS_TLS", "true")
	defer func() {
		os.Unsetenv("HEPLIFY_API_SETTINGS_PORT")
		os.Unsetenv("HEPLIFY_API_SETTINGS_HOST")
		os.Unsetenv("HEPLIFY_API_SETTINGS_USERNAME")
		os.Unsetenv("HEPLIFY_API_SETTINGS_TLS")
	}()

	cfg := &Config{}
	eu := NewEnvUpdater()
	_, err := eu.UpdateFromEnv(cfg)
	if err != nil {
		t.Fatalf("UpdateFromEnv error: %v", err)
	}

	if cfg.ApiSettings.Port != 8080 {
		t.Errorf("ApiSettings.Port: got %d, want 8080", cfg.ApiSettings.Port)
	}
	if cfg.ApiSettings.Host != "0.0.0.0" {
		t.Errorf("ApiSettings.Host: got %q, want 0.0.0.0", cfg.ApiSettings.Host)
	}
	if cfg.ApiSettings.Username != "admin" {
		t.Errorf("ApiSettings.Username: got %q, want admin", cfg.ApiSettings.Username)
	}
	if !cfg.ApiSettings.TLS {
		t.Error("ApiSettings.TLS should be true")
	}
}

// TestEnvUpdaterFieldCoverage checks that all expected config sections are
// represented in the generated ENV mappings.
func TestEnvUpdaterFieldCoverage(t *testing.T) {
	eu := NewEnvUpdater()
	if err := eu.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}

	expectedPrefixes := []string{
		"HEPLIFY_SOCKET__",
		"HEPLIFY_TRANSPORT__",
		"HEPLIFY_PROTOCOL__",
		"HEPLIFY_LOG_SETTINGS_",
		"HEPLIFY_SIP_SETTINGS_",
		"HEPLIFY_HEP_SETTINGS_",
		"HEPLIFY_RTCP_SETTINGS_",
		"HEPLIFY_SYSTEM_SETTINGS_",
		"HEPLIFY_PROMETHEUS_SETTINGS_",
		"HEPLIFY_API_SETTINGS_",
		"HEPLIFY_DEBUG_SETTINGS_",
		"HEPLIFY_FILTER_INCLUDE__",
		"HEPLIFY_FILTER_EXCLUDE__",
	}

	mappings := eu.fieldMappings
	t.Logf("total mappings: %d", len(mappings))

	for _, want := range expectedPrefixes {
		found := false
		for _, m := range mappings {
			if strings.HasPrefix(m.EnvName, want) {
				found = true
				break
			}
		}
		if found {
			t.Logf("  ✓ %s", want)
		} else {
			t.Errorf("  ✗ no mapping found with prefix %s", want)
		}
	}
}

// TestEnvUpdaterIdempotent verifies that calling UpdateFromEnv twice does not
// corrupt the config.
func TestEnvUpdaterIdempotent(t *testing.T) {
	os.Setenv("HEPLIFY_LOG_SETTINGS_LEVEL", "warn")
	defer os.Unsetenv("HEPLIFY_LOG_SETTINGS_LEVEL")

	cfg := &Config{}
	eu := NewEnvUpdater()

	for i := 0; i < 3; i++ {
		if _, err := eu.UpdateFromEnv(cfg); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if cfg.LogSettings.Level != "warn" {
		t.Errorf("LogSettings.Level: got %q, want warn", cfg.LogSettings.Level)
	}
}
