<img src="https://user-images.githubusercontent.com/20154956/33374900-42c9253a-d508-11e7-8a9e-ea73a515a514.png">  
heplify is captagents little brother, optimized for speed and simplicity. It's a single binary which you can run 
on Linux, ARM, MIPS, Windows to capture IPv4 or IPv6 packets and send them to Homer. Heplify is able to send 
SIP, correlated RTCP, RTCPXR, DNS, Logs into homer. 
It's able to handle fragmented and duplicate packets out of the box.  

### Requirements
Linux: None if you use the binary from the releases  
Windows: [WinPcap](https://www.winpcap.org/install/default.htm)  

### Installation
Linux: Download [heplify](https://github.com/sipcapture/heplify/releases) and execute 'chmod +x heplify'  
Windows: Download [heplify.exe](https://github.com/sipcapture/heplify/releases)  

### Usage
```bash
  -i    Listen on interface (default "any")
  -t    Capture types are [pcap, af_packet] (default "pcap")
  -m    Capture modes [SIP, SIPDNS, SIPLOG, SIPRTP, SIPRTCP] (default "SIPRTCP")
  -pr   Portrange to capture SIP (default "5060-5090")
  -hs   HEP UDP server address (default "127.0.0.1:9060")
  -hi   HEP Node ID (default 2002)
  -di   Discard uninteresting packets
  -fi   Filter interesting packets
  -rf   Read pcap file
  -wf   Path to write pcap file
  -zf   Enable pcap compression
  -e    Log to stderr and disable syslog/file output
  -d    Enable certain debug selectors [fragment,layer,payload,rtp,rtcp,sdp]
```

### Examples
```bash
# Capture SIP and RTCP packets on any interface and send them to 127.0.0.1:9060
./heplify

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print info to stdout
./heplify -hs 192.168.1.1:9060 -e

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print debug selectors
./heplify -hs 192.168.1.1:9060 -e -d fragment,payload,rtcp

# Capture SIP and RTCP packets with custom SIP port range on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -pr 6000-6010 -hs 192.168.1.1:9060

# Capture SIP and RTCP packets on eth2, send them to homer and compressed to /srv/pcapdumps/
./heplify -i eth2 -hs 192.168.1.1:9060 -wf /srv/pcapdumps/ -zf

# Read example/rtp_rtcp_sip.pcap and send SIP and correlated RTCP packets to 192.168.1.1:9060
./heplify -rf example/rtp_rtcp_sip.pcap -hs 192.168.1.1:9060

# Capture and send packets except REGISTER to 192.168.1.1:9060. Whitespace is needed as we look at the CSeq
./heplify -hs 192.168.1.1:9060 -di " REGISTER"

```
