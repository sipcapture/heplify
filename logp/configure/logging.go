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

type StringsFlag struct {
	list      *[]string
	isDefault bool
	flag      *flag.Flag
}

func init() {
	flag.BoolVar(&verbose, "v", false, "Log at INFO level")
	flag.BoolVar(&toStderr, "e", false, "Log to stderr and disable syslog/file output")
	StringArrVarFlag(nil, &debugSelectors, "d", "Enable certain debug selectors [fragment,layer,payload,rtcp,rtcpfail,sdp]")
}

func (f *StringsFlag) String() string {
	return ""
}

func (f *StringsFlag) Set(v string) error {
	// Ignore duplicates, can be caused by multiple flag parses
	if f.isDefault {
		*f.list = []string{v}
	} else {
		for _, old := range *f.list {
			if old == v {
				return nil
			}
		}
		*f.list = append(*f.list, v)
	}
	f.isDefault = false
	return nil
}

func (f *StringsFlag) Register(fs *flag.FlagSet, name, usage string) {
	if f.flag != nil {
		panic("StringsFlag is already registered")
	}

	fs.Var(f, name, usage)
	f.flag = fs.Lookup(name)
	if f.flag == nil {
		panic("Failed to lookup registered flag")
	}

	if len(*f.list) > 0 {
		f.flag.DefValue = (*f.list)[0]
	}
}

func StringArrVarFlag(fs *flag.FlagSet, arr *[]string, name, usage string) *StringsFlag {
	if fs == nil {
		fs = flag.CommandLine
	}
	f := NewStringsFlag(arr)
	f.Register(fs, name, usage)
	return f
}

func NewStringsFlag(arr *[]string) *StringsFlag {
	if arr == nil {
		panic("No target array")
	}
	return &StringsFlag{list: arr, isDefault: true}
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
