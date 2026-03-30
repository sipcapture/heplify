//go:build !windows

package script

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
)

// WatchSIGHUP starts a goroutine that reloads the script on SIGHUP.
func (e *Engine) WatchSIGHUP() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ch:
				log.Info().Msg("Received SIGHUP — reloading Lua script")
				if err := e.Reload(); err != nil {
					log.Error().Err(err).Msg("Lua script reload failed")
				}
			case <-e.stopCh:
				return
			}
		}
	}()
}
