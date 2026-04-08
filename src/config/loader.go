package config

import (
	"fmt"

	"github.com/spf13/viper"
)

var Current *Config

func LoadConfig(path string) (*Config, error) {
	v := viper.New()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("heplify")
		v.SetConfigType("json")
		v.AddConfigPath("/etc/heplify/")
		v.AddConfigPath("./")
	}

	v.SetDefault("rtcp_settings.active", true)
	v.SetDefault("api_settings.tls", false)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Apply HEPLIFY_* environment variable overrides on top of the file
	// config. This covers all fields including slice elements and nested
	// structs that viper's AutomaticEnv cannot address.
	eu := NewEnvUpdater()
	if _, err := eu.UpdateFromEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to apply env overrides: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	Current = &cfg
	return &cfg, nil
}
