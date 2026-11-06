package sniffer

import (
	"net"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"
)

// parseTunnelSources turns tunnel_allowed_sources into a check function.
// It returns nil (allow all) for an empty list. Invalid entries are logged
// and skipped; config validation rejects them earlier.
func parseTunnelSources(entries []string) func(net.IP) bool {
	var prefixes []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		p, err := parsePrefixOrAddr(e)
		if err != nil {
			log.Warn().Str("entry", e).Err(err).Msg("Ignoring invalid tunnel_allowed_sources entry")
			continue
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil
	}
	return func(ip net.IP) bool {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return false
		}
		addr = addr.Unmap()
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
