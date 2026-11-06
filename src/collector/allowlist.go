package collector

import (
	"fmt"
	"net"
	"strings"
)

// allowList holds the source networks allowed to send HEP. A nil list allows all.
type allowList struct {
	nets []*net.IPNet
}

func newAllowList(entries []string) (*allowList, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	a := &allowList{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, fmt.Errorf("collector allowed_cidrs: invalid entry %q", e)
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			a.nets = append(a.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("collector allowed_cidrs: %w", err)
		}
		a.nets = append(a.nets, n)
	}
	return a, nil
}

func (a *allowList) allowedIP(ip net.IP) bool {
	if a == nil {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *allowList) allowedAddr(addr net.Addr) bool {
	if a == nil {
		return true
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return a.allowedIP(v.IP)
	case *net.TCPAddr:
		return a.allowedIP(v.IP)
	}
	return a.allowedHostPort(addr.String())
}

func (a *allowList) allowedHostPort(hostport string) bool {
	if a == nil {
		return true
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	return a.allowedIP(net.ParseIP(host))
}
