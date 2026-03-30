package config

import (
	"fmt"
	"strings"

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

	v.SetEnvPrefix("HEPLIFYNG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("rtcp_settings.active", true)
	v.SetDefault("api_settings.tls", false)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	Current = &cfg
	return &cfg, nil
}
