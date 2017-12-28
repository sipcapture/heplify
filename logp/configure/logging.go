package configure

import (
	"flag"
	"strings"

	"github.com/negbie/heplify/logp"
)

// CLI flags for configuring logging.
var (
	verbose        bool
	toStderr       bool
	debugSelectors []string
)

func init() {
	flag.BoolVar(&verbose, "v", false, "Log at INFO level")
	flag.BoolVar(&toStderr, "e", false, "Log to stderr and disable syslog/file output")
}

// Logging builds a logp.Config based on the given common.Config and the specified
// CLI flags.
func Logging(beatName string) error {
	config := logp.DefaultConfig()
	config.Beat = beatName

	applyFlags(&config)
	return logp.Configure(config)
}

func applyFlags(cfg *logp.Config) {
	if toStderr {
		cfg.ToStderr = true
	}
	if cfg.Level > logp.InfoLevel {
		cfg.Level = logp.InfoLevel
	}
	for _, selectors := range debugSelectors {
		cfg.Selectors = append(cfg.Selectors, strings.Split(selectors, ",")...)
	}

	// Elevate level if selectors are specified on the CLI.
	if len(cfg.Selectors) > 0 {
		cfg.Level = logp.DebugLevel
	}
}
