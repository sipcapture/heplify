# heplify
heplify is captagents little brother. While it offers a compareable performance the design goal was simplicity.
It's a single binary which you can run to capture packets and send them to Homer. 
Right now heplify is able to send SIP, correlated RTCP and very basic DNS, LOG or TLS handshakes into homer. It's able to 
handle fragmented and duplicate packets out of the box.
<img align="right" width="300" src="https://user-images.githubusercontent.com/20154956/30700149-0278a246-9ee7-11e7-8aef-8d68baef554a.png">
### Requirements
* None if you use the binary from the [releases](https://github.com/sipcapture/heplify/releases)  

### Installation
Simply grab it from the [releases](https://github.com/sipcapture/heplify/releases)  
chmod +x heplify  

### Usage
```bash
  -i    Listen on interface
  -t    Capture types are [pcap, af_packet] (default "pcap")
  -m    Capture modes [DNS, LOG, SIP, SIPRTCP, TLS] (default "SIP")
  -pr   Portrange to capture SIP (default "5060-5090")
  -hs   HEP Server address (default "127.0.0.1:9060")
  -di   Discard uninteresting packets
  -fi   Filter interesting packets
  -rf   Read packets from pcap file
  -wf   Write packets to pcap file
  -e    Log to stderr and disable syslog/file output
  -l    Log level [debug, info, warning, error] (default "info")
```

### Examples
```bash
# Capture SIP packets on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -hs 192.168.1.1:9060 &

# Capture SIP packets on eth2 and send them to 192.168.1.1:9060. Print debug log level to stdout
./heplify -i eth2 -hs 192.168.1.1:9060 -e -l debug

# Capture SIP packets with custom port range on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -pr 6000-6010 -hs 192.168.1.1:9060 &

# Use af_packet to capture SIP and correlated RTCP packets on eth2 and send them to 192.168.1.1:9060
./heplify -i eth2 -hs 192.168.1.1:9060 -t af_packet -m SIPRTCP &

# Capture SIP packets on eth2 and save them to pcap into current folder
./heplify -i eth2 -wf capture.pcap -t af_packet &

# Read example/rtp_rtcp_sip.pcap and send SIP and correlated RTCP packets to 192.168.1.1:9060
./heplify -rf example/rtp_rtcp_sip.pcap -m SIPRTCP -hs 192.168.1.1:9060 &

```