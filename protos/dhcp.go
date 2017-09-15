package protos

import (
	"net"

	"github.com/google/gopacket/layers"
)

type DHCP struct {
	Operation    layers.DHCPOp
	HardwareType layers.LinkType
	HardwareLen  uint8
	HardwareOpts uint8
	Xid          uint32
	Secs         uint16
	Flags        uint16
	ClientIP     net.IP
	YourClientIP net.IP
	NextServerIP net.IP
	RelayAgentIP net.IP
	ClientHWAddr net.HardwareAddr
	ServerName   []byte
	File         []byte
	Options      layers.DHCPOptions
}

// TODO: complete this
func NewDHCP(dhcp *layers.DHCPv4) (d *DHCP) {
	d = &DHCP{}
	d.Xid = dhcp.Xid

	return d
}
