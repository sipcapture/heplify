//go:build windows

package script

import "github.com/rs/zerolog/log"

// WatchSIGHUP is a no-op on Windows (SIGHUP does not exist).
func (e *Engine) WatchSIGHUP() {
	log.Warn().Msg("SIGHUP-based script reload is not supported on Windows")
}
