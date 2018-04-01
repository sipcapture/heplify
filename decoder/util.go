package decoder

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/negbie/heplify/logp"
)

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

func fastHash(s []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return
}

func ipToint(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func isPrivIP(IP net.IP) (p bool) {
	_, classA, _ := net.ParseCIDR("10.0.0.0/8")
	_, classB, _ := net.ParseCIDR("172.16.0.0/12")
	_, classC, _ := net.ParseCIDR("192.168.0.0/16")
	p = classA.Contains(IP) || classB.Contains(IP) || classC.Contains(IP)
	return p
}

func (d *Decoder) flushFragments() {
	for {
		<-time.After(1 * time.Minute)
		go func() {
			d.defragger.DiscardOlderThan(time.Now().Add(-1 * time.Minute))
		}()
	}
}

func (p *Packet) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Version   byte
		Protocol  byte
		SrcIP     net.IP
		DstIP     net.IP
		SrcPort   uint16
		DstPort   uint16
		Tsec      uint32
		Tmsec     uint32
		ProtoType byte
		NodeID    uint32
		NodePW    string
		Payload   string
		CID       string
		Vlan      uint16
	}{
		Version:   p.Version,
		Protocol:  p.Protocol,
		SrcIP:     p.SrcIP,
		DstIP:     p.DstIP,
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Tsec:      p.Tsec,
		Tmsec:     p.Tmsec,
		ProtoType: p.ProtoType,
		NodeID:    p.NodeID,
		NodePW:    string(p.NodePW),
		Payload:   string(p.Payload),
		CID:       string(p.CID),
		Vlan:      p.Vlan,
	})
}

func (d *Decoder) printPacketStats() {
	logp.Info("Packets since last minute IPv4: %d, IPv6: %d, UDP: %d, TCP: %d, RTCP: %d, RTCPFail: %d, DNS: %d, duplicate: %d, fragments: %d, unknown: %d",
		d.ip4Count, d.ip6Count, d.udpCount, d.tcpCount, d.rtcpCount, d.rtcpFailCount, d.dnsCount, d.dupCount, d.fragCount, d.unknownCount)
	d.ip4Count, d.ip6Count, d.udpCount, d.tcpCount, d.rtcpCount, d.rtcpFailCount, d.dnsCount, d.dupCount, d.fragCount, d.unknownCount = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
}

func (d *Decoder) printSIPCacheStats() {
	logp.Info("SIPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.SIPCache.EntryCount(), d.SIPCache.LookupCount(), d.SIPCache.HitCount(), d.SIPCache.ExpiredCount(), d.SIPCache.OverwriteCount())
	d.SIPCache.ResetStatistics()
}

func (d *Decoder) printSDPCacheStats() {
	logp.Info("SDPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.SDPCache.EntryCount(), d.SDPCache.LookupCount(), d.SDPCache.HitCount(), d.SDPCache.ExpiredCount(), d.SDPCache.OverwriteCount())
	d.SDPCache.ResetStatistics()
}

func (d *Decoder) printRTCPCacheStats() {
	logp.Info("RTCPCache EntryCount: %v, LookupCount: %v, HitCount: %v, ExpiredCount: %v, OverwriteCount: %v",
		d.RTCPCache.EntryCount(), d.RTCPCache.LookupCount(), d.RTCPCache.HitCount(), d.RTCPCache.ExpiredCount(), d.RTCPCache.OverwriteCount())
	d.RTCPCache.ResetStatistics()
}

func (d *Decoder) printStats() {
	for {
		<-time.After(60 * time.Second)
		go func() {
			d.printPacketStats()
			if runtime.GOARCH == "amd64" {
				d.printSIPCacheStats()
				d.printSDPCacheStats()
				d.printRTCPCacheStats()
			}
		}()
	}
}

func unmarshalNG(data []byte) ([]byte, interface{}, error) {
	cookieEnd := bytes.Index(data, []byte(" ")) + 1
	cookieLen := len(data[:cookieEnd])
	if cookieLen < 6 || cookieLen > 20 {
		return nil, nil, errors.New("ng: invalid cookie length")
	}
	result, _, err := parseNG(data[cookieEnd:])
	if err != nil {
		return nil, nil, err
	}

	return data[:cookieEnd], result, nil
}

func readUntil(data []byte, symbol byte) ([]byte, int, bool) {
	for i, b := range data {
		if b == symbol {
			return data[:i], i, true
		}
	}
	return nil, 0, false
}

func parseNG(data []byte) (interface{}, int, error) {
	switch data[0] {
	case 'i':
		integerBuffer, length, ok := readUntil(data[1:], 'e')
		if !ok {
			return nil, 0, errors.New("ng: invalid integer field")
		}

		integer, err := strconv.ParseInt(string(integerBuffer), 10, 64)
		if err != nil {
			return nil, 0, err
		}

		return integer, length + 2, nil

	case 'l':
		list := []interface{}{}
		totalLength := 2
		data = data[1:]
		for {
			if len(data) == 0 {
				return nil, 0, errors.New("ng: invalid list field")
			}

			if data[0] == 'e' {
				return list, totalLength, nil
			}

			value, length, err := parseNG(data)
			if err != nil {
				return nil, 0, err
			}

			list = append(list, value)
			data = data[length:]
			totalLength += length
		}

	case 'd':
		dictionary := map[string]interface{}{}
		totalLength := 2
		data = data[1:]
		for {
			if len(data) == 0 {
				return nil, 0, errors.New("ng: invalid dictionary field")
			}

			if data[0] == 'e' {
				return dictionary, totalLength, nil
			}

			value, length, err := parseNG(data)
			if err != nil {
				return nil, 0, err
			}

			key, ok := value.([]byte)
			if !ok {
				return nil, 0, errors.New("ng: non-string dictionary key")
			}

			data = data[length:]
			totalLength += length
			value, length, err = parseNG(data)
			if err != nil {
				return nil, 0, err
			}

			dictionary[string(key)] = value
			data = data[length:]
			totalLength += length
		}

	default:
		stringLengthBuffer, length, ok := readUntil(data, ':')
		if !ok {
			return nil, 0, errors.New("ng: invalid string field")
		}

		stringLength, err := strconv.ParseInt(string(stringLengthBuffer), 10, 64)
		if err != nil {
			return nil, 0, err
		}

		endPosition := length + 1 + int(stringLength)
		return data[length+1 : endPosition], endPosition, nil
	}
}
