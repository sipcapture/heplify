<img src="https://user-images.githubusercontent.com/20154956/33374900-42c9253a-d508-11e7-8a9e-ea73a515a514.png">  
heplify is captagents little brother. While it offers a compareable performance the design goal was simplicity. 
It's a single binary which you can run to capture packets and send them to Homer. 
Right now heplify is able to send SIP, correlated RTCP, RTCPXR and very basic DNS, LOG or TLS handshakes into homer. 
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
  -m    Capture modes [SIPDNS, SIPLOG, SIPRTCP, SIP, TLS] (default "SIPRTCP")
  -pr   Portrange to capture SIP (default "5060-5090")
  -hs   HEP Server address (default "127.0.0.1:9060")
  -di   Discard uninteresting packets
  -fi   Filter interesting packets
  -rf   Read pcap file
  -wf   Path to write pcap file
  -zf   Gzip pcap file
  -e    Log to stderr and disable syslog/file output
  -l    Log level [debug, info, warning, error] (default "info")
  -d    Enable certain debug selectors [fragment, layer, payload, rtcp, rtcpfail, sdp]
```

### Examples
```bash
# Capture SIP and RTCP packets on any interface and send them to 127.0.0.1:9060
./heplify

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print debug to stdout
./heplify -hs 192.168.1.1:9060 -e -l debug

# Capture SIP and RTCP packets on any interface and send them to 192.168.1.1:9060. Print debug selectors
./heplify -hs 192.168.1.1:9060 -e -d fragment,payload,rtcp

# Capture SIP and RTCP packets with custom port range on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -pr 6000-6010 -hs 192.168.1.1:9060

# Capture SIP and RTCP packets on eth2, send them to homer and compressed to /srv/pcapdumps/
./heplify -i eth2 -hs 192.168.1.1:9060 -wf /srv/pcapdumps/ -zf

# Read example/rtp_rtcp_sip.pcap and send SIP and correlated RTCP packets to 192.168.1.1:9060
./heplify -rf example/rtp_rtcp_sip.pcap -hs 192.168.1.1:9060

```