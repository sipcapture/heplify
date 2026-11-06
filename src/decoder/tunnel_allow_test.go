package decoder

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// vxlanSIP builds Ethernet/IPv4(outer)/UDP:4789/VXLAN/Ethernet/IPv4/UDP:5060/SIP.
func vxlanSIP(t *testing.T, outerSrc string) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	inner := gopacket.NewSerializeBuffer()
	innerIP := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 0, 2, 10}, DstIP: net.IP{192, 0, 2, 20}}
	innerUDP := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	_ = innerUDP.SetNetworkLayerForChecksum(innerIP)
	if err := gopacket.SerializeLayers(inner, opts,
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4},
		innerIP, innerUDP, gopacket.Payload("OPTIONS sip:x SIP/2.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	outer := gopacket.NewSerializeBuffer()
	outerIP := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(outerSrc).To4(), DstIP: net.IP{10, 0, 0, 2}}
	outerUDP := &layers.UDP{SrcPort: 40000, DstPort: 4789}
	_ = outerUDP.SetNetworkLayerForChecksum(outerIP)
	if err := gopacket.SerializeLayers(outer, opts,
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 0, 0, 0, 0, 3}, DstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 4}, EthernetType: layers.EthernetTypeIPv4},
		outerIP, outerUDP, &layers.VXLAN{ValidIDFlag: true, VNI: 1}, gopacket.Payload(inner.Bytes())); err != nil {
		t.Fatal(err)
	}
	return outer.Bytes()
}

func TestTunnelSourceAllowList(t *testing.T) {
	d := NewDecoder(layers.LinkTypeEthernet)
	d.TunnelSourceAllowed = func(ip net.IP) bool { return ip.Equal(net.IP{10, 0, 0, 1}) }

	pkt, _ := d.Decode(vxlanSIP(t, "10.0.0.1"), gopacket.CaptureInfo{})
	if pkt == nil || !pkt.SrcIP.Equal(net.IP{192, 0, 2, 10}) {
		t.Fatalf("allowed VXLAN endpoint: expected inner packet, got %+v", pkt)
	}
	if pkt, _ := d.Decode(vxlanSIP(t, "10.0.0.66"), gopacket.CaptureInfo{}); pkt != nil {
		t.Fatalf("VXLAN from unknown endpoint should be dropped, got src %v", pkt.SrcIP)
	}
}
