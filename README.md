<img src="https://user-images.githubusercontent.com/20154956/30700149-0278a246-9ee7-11e7-8aef-8d68baef554a.png" width="100">
# heplify
heplify is captagents little brother. While it offers a compareable performance the design goal was simplicity.
It's a single binary which you can place on your linux or windows machine. Just run it to capture packets and 
send them to Homer. Right now heplify is able to send SIP, DNS, LOG or TLS handshakes into homer. It's able to 
handle fragmented and duplicate packets out of the box.

### Requirements
* libpcap

On Debian/Ubuntu: sudo apt-get install libpcap-dev  
On CentOS/RHEL: yum install libpcap-devel  
On Windows: install WinPcap  

### Installation
Simply grab it from the [releases](https://github.com/sipcapture/heplify/releases)  
chmod +x heplify  

### Usage
```bash
  -i    Listen on interface
  -t    Capture types are [af_packet, pcap, file] (default "pcap")
  -m    Capture modes [DNS, LOG, SIP, TLS] (default "SIP")
  -hs   HEP Server address (default "127.0.0.1:9060")
  -di   Discard uninteresting packets like SIP OPTIONS, HTTP Requests ...
  -fi   Filter out interesting packets like SIP INVITES, Handshakes ...
  -rf   Read packets from file. Please use -t file
  -wf   Write packets to file
  -e    Log to stderr and disable syslog/file output
  -l    Log level [debug, info, warning, error] (default "info")
```

### Examples
```bash
# Capture SIP packets on eth2 and send them to Homer under 192.168.1.1:9060
./heplify -i eth2 -hs "192.168.1.1:9060"

# Print default log level to stdout
./heplify -i eth2 -hs "192.168.1.1:9060" -e

# Print debug log level to stdout
./heplify -i eth2 -hs "192.168.1.1:9060" -e -l debug

# Capture LOG packets on eth2 and send them to Homer under 192.168.1.1:9060
./heplify -i eth2 -hs "192.168.1.1:9060" -m LOG

# Capture SIP packets on eth2 and save them to pcap into current folder
./heplify -i eth2 -wf capture.pcap

# Read pcap file from current folder and send it's content to Homer under 192.168.1.1:9060
./heplify -i eth2 -t file -rf capture.pcap -hs "192.168.1.1:9060"

```