package config

import "testing"

func TestEnvNewSecurityOptions(t *testing.T) {
	t.Setenv("HEPLIFY_COLLECTOR_SETTINGS_ALLOWED_CIDRS__0", "10.0.0.0/8")
	t.Setenv("HEPLIFY_COLLECTOR_SETTINGS_AUTH_TOKEN", "tok")
	t.Setenv("HEPLIFY_SCRIPT_SETTINGS_TIMEOUT_MS", "250")
	t.Setenv("HEPLIFY_TRANSPORT__0__CA_FILE", "/ca.pem")
	eu := NewEnvUpdater()
	if err := eu.Initialize(); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	if _, err := eu.UpdateFromEnv(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.CollectorSettings.AllowedCIDRs) != 1 || cfg.CollectorSettings.AllowedCIDRs[0] != "10.0.0.0/8" ||
		cfg.CollectorSettings.AuthToken != "tok" || cfg.ScriptSettings.TimeoutMs != 250 ||
		len(cfg.TransportSettings) == 0 || cfg.TransportSettings[0].CAFile != "/ca.pem" {
		t.Fatalf("env not applied: %+v %+v %+v", cfg.CollectorSettings, cfg.ScriptSettings, cfg.TransportSettings)
	}
}
