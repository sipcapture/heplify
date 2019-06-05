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
  -i    Listen on interface (default "any")
  -nt   Network types are [udp, tcp, tls] (default "udp")
  -t    Capture types are [pcap, af_packet] (default "pcap")
  -m    Capture modes [SIP, SIPDNS, SIPLOG, SIPRTCP] (default "SIPRTCP")
  -pr   Portrange to capture SIP (default "5060-5090")
  -hs   HEP UDP server address (default "127.0.0.1:9060")
  -hi   HEP Node ID (default 2002)
  -di   Discard uninteresting packets by string
  -dim  Discard uninteresting SIP packets by CSeq [OPTIONS,NOTIFY]
  -fi   Filter interesting packets by string
  -rf   Read PCAP file
  -rs   Use original timestamps when reading PCAP file
  -wf   Path to write pcap file
  -zf   Enable pcap compression
  -e    Log to stderr and disable syslog/file output
  -d    Enable certain debug selectors [fragment,layer,payload,rtp,rtcp,sdp]
```

## Examples

```bash
# Capture SIP and RTCP packets on any interface and send them to 127.0.0.1:9060
./heplify

# Capture SIP and RTCP packets on any interface and send them via TLS to 192.168.1.1:9060
./heplify -hs 192.168.1.1:9060 -nt tls

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Use a HEPNodeName
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

# Capture and send packets except SIP OPTIONS and NOTIFY to 192.168.1.1:9060.
./heplify -hs 192.168.1.1:9060 -dim OPTIONS,NOTIFY

```

----

### Made by Humans

This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.

If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest) 
