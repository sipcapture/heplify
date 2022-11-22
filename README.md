<img src="https://user-images.githubusercontent.com/20154956/33374900-42c9253a-d508-11e7-8a9e-ea73a515a514.png">
heplify is captagents little brother, optimized for speed and simplicity. It's a single binary which you can run
on Linux, ARM, MIPS, Windows to capture IPv4 or IPv6 packets and send them to Homer. Heplify is able to send
SIP, correlated RTCP, RTCPXR, DNS, Logs into homer.
It's able to handle fragmented and duplicate packets out of the box.

## Requirements

### Linux

None if you use the binary from the releases

### Windows

[WinPcap](https://www.winpcap.org/install/default.htm)

## Installation

### Linux

Download [heplify](https://github.com/sipcapture/heplify/releases) and execute 'chmod +x heplify'

### Windows

Download [heplify.exe](https://github.com/sipcapture/heplify/releases)

### Development build

If you have Go 1.11+ installed, build the latest heplify binary by running `make`.

You can also build a docker image:

```bash
docker build --no-cache -t sipcapture/heplify:latest -f docker/heplify/Dockerfile .
```

## Usage

```bash
 -assembly_debug_log
	If true, the github.com/google/gopacket/tcpassembly library will log verbose debugging information (at least one line per packet)
  -assembly_memuse_log
	If true, the github.com/google/gopacket/tcpassembly library will log information regarding its memory use every once in a while.
  -b int
	Interface buffersize (MB) (default 32)
  -d string
	Enable certain debug selectors [defrag,layer,payload,rtp,rtcp,sdp]
  -dd
	Deduplicate packets
  -di string
	Discard uninteresting packets by any string
  -dim string
	Discard uninteresting SIP packets by CSeq [OPTIONS,NOTIFY]
  -diip string
	Discard uninteresting SIP packets by Source or Destination IP(s)
  -disip string
	Discard uninteresting SIP packets by Source IP(s)
  -didip string
	Discard uninteresting SIP packets by Destination IP(s)
  -e	
	Log to stderr and disable syslog/file output
  -erspan
	erspan
  -fg uint
	Fanout group ID for af_packet
  -fi string
	Filter interesting packets by any string
  -fw int
	Fanout worker count for af_packet (default 4)
  -hi uint
	HEP node ID (default 2002)
  -hin
	HEP collector listening protocol, address and port (example: "tcp:10.10.99.10:9060")
  -hn string
	HEP node Name
  -hp string
	HEP node PW
  -hs string
	HEP server destination address and port (default "127.0.0.1:9060")
  -i string
	Listen on interface (default "any")
  -l string
	Log level [debug, info, warning, error] (default "info")
  -lp int
	Loop count over ReadFile. Use 0 to loop forever (default 1)
  -m string
	Capture modes [SIP, SIPDNS, SIPLOG, SIPRTCP] (default "SIPRTCP")
  -n string
	Log filename (default "heplify.log")
  -nt string
	Network types are [udp, tcp, tls] (default "udp")
  -bpf string
	Custom bpf filter (default "")
  -o	
	Read packet for packet
  -p string
	Log filepath (default "./")
  -pr string
	Portrange to capture SIP (default "5060-5090")
  -protobuf
	Use Protobuf on wire
  -rf string
	Read pcap file
  -rs
	Use packet timestamps with maximum pcap read speed
  -rt int
	Pcap rotation time in minutes (default 60)
  -s int
	Snaplength (default 8192)
  -sl
	Log to syslog
  -t string
	Capture types are [pcap, af_packet] (default "pcap")
  -tcpassembly
	If true, tcpassembly will be enabled
  -tcpsendretries uint
	Number of retries for sending before giving up and reconnecting (default 64)
  -version
	Show heplify version
  -vlan
	vlan
  -wf string
	Path to write pcap file
  -zf
	Enable pcap compression
```

## Examples

```bash
# Capture SIP and RTCP packets on any interface and send them to 127.0.0.1:9060
./heplify

# Capture SIP and RTCP packets on any interface and send them via TLS to 192.168.1.1:9060
./heplify -hs 192.168.1.1:9060 -nt tls

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Use a someNodeName
./heplify -hs 192.168.1.1:9060 -hn someNodeName

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print info to stdout
./heplify -hs 192.168.1.1:9060 -e

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060 and 192.168.2.2:9060
./heplify -hs "192.168.1.1:9060,192.168.2.2:9060"

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print debug selectors
./heplify -hs 192.168.1.1:9060 -e -d fragment,payload,rtcp

# Capture SIP and RTCP packets with custom SIP port range on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -pr 6000-6010 -hs 192.168.1.1:9060

# Capture SIP and RTCP packets on eth2, send them to homer and compressed to /srv/pcapdumps/
./heplify -i eth2 -hs 192.168.1.1:9060 -wf /srv/pcapdumps/ -zf

# Read example/rtp_rtcp_sip.pcap and send SIP and correlated RTCP packets to 192.168.1.1:9060
./heplify -rf example/rtp_rtcp_sip.pcap -hs 192.168.1.1:9060

# Capture and send packets except SIP OPTIONS and NOTIFY to 192.168.1.1:9060
./heplify -hs 192.168.1.1:9060 -dim OPTIONS,NOTIFY

# Capture SIP packet with HPERM encapsulation on port 7932 and interface eth2, send to 192.168.1.1:9060 and print debug info on stdout
./heplify -i eth2 -bpf "port 7932" -hs 192.168.1.1:9060 -l debug -e

# Run heplify in "HEP Collector" mode in order to receive HEP input via TCP on port 9060 and fork (output) to two HEP servers listening on port 9063
./heplify -e -hs HEPServer1:9063,HEPserver2:9063 -hin tcp:1.2.3.4:9060


```
### Made by Humans

This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.

If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)
