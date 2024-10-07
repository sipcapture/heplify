<a href="https://sipcapture.org"><img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/></a>

<img src="https://github.com/sipcapture/heplify/assets/1423657/7a36896d-0bd3-4cf3-9525-0513e67aee46">

<img src="https://img.shields.io/docker/pulls/sipcapture/heplify">

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

If you have Go 1.18+ installed, build the latest heplify binary by running `make`.

Now you should install LUA Jit:

* Compile from sources:  
  
  Install luajit dev libary
  
  `apt-get install libluajit-5.1-dev`
  
  or 
  
  `yum install luajit-devel`

  or for macOS

  ```sh
  # Assuming brew installs to /usr/local/
  brew install lua@5.1 luajit
  ln -s /usr/local/lib/pkgconfig/luajit.pc /usr/local/lib/pkgconfig/luajit-5.1.pc
  export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/
  ```
  
  [install](https://golang.org/doc/install) Go 1.11+

  `go build cmd/heplify/heplify.go`
  
  

### Docker

You can also build a docker image:

```bash
docker build --no-cache -t sipcapture/heplify:latest -f docker/heplify/Dockerfile .
```

You can use the image using docker compose: 

```
  heplify:
    image: sipcapture/heplify:latest
    user: 1000:1000
    cap_add:
      - CAP_NET_ADMIN
      - CAP_NET_RAW
    command:
      ./heplify -e -hs ${HOMER_DST}:9060 -m SIP -dd -zf -l info
    network_mode: host
    restart: unless-stopped
```

## Usage

```bash
 -assembly_debug_log
	If true, the github.com/google/gopacket/tcpassembly library will log verbose debugging information (at least one line per packet)
  -assembly_memuse_log
	If true, the github.com/google/gopacket/tcpassembly library will log information regarding its memory use every once in a while.
  -b int
	Interface buffersize (MB) (default 32)
  -bpf string
        Custom BPF to capture packets
  -collectonlysip
        collect only sip
  -d string
	Enable certain debug selectors [defrag,layer,payload,rtp,rtcp,sdp]
  -dd
	Deduplicate packets
  -di string
	Discard uninteresting packets by any string
  -didip string
	Discard uninteresting SIP packets by Destination IP(s)
  -diip string
	Discard uninteresting SIP packets by Source or Destination IP(s)
  -dim string
	Discard uninteresting SIP packets by Method [OPTIONS,NOTIFY]
  -disip string
	Discard uninteresting SIP packets by Source IP(s)
  -e	
	Log to stderr and disable syslog/file output
  -eof-exit
        Exit once done reading pcap file
  -erspan
	erspan
  -fg uint
	Fanout group ID for af_packet
  -fi string
	Filter interesting packets by any string
  -fnum int
        The total num of log files to keep (default 7)
  -fsize uint
        The rotate size per log file based on byte (default 10485760)
  -fw int
	Fanout worker count for af_packet (default 4)
  -hep-buffer-activate
        enable buffer messages if connection to HEP server broken
  -hep-buffer-debug
        enable debug buffer messages
  -hep-buffer-file string
        filename and location for hep-buffer file (default "HEP-Buffer.dump")
  -hep-buffer-max-size string
        max buffer size, can be B, KB, MB, GB, TB. By default - unlimited (default "0")
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
  -keepalive uint
        keep alive internal - 5 seconds by default. 0 - disable (default 5)
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
  -prometheus string
        prometheus metrics - ip:port. By default all IPs (default ":8090")
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
  -script-file string
        Script file to execute on each packet
  -script-hep-filter string
        HEP filter for script, comma separated list of HEP types (default "1")
  -sipassembly
        If true, sipassembly will be enabled
  -skipverify
        skip certifcate validation
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
  -script-file string
    	LUA script file path to execute on each packet
  -script-hep-filter string
    	HEP Type filter for LUA script, comma separated list (default "1")

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

# Capture SIP packet with VXLAN encapsulation on port 4789 and interface eth0, send to 192.168.1.1:9060 and print debug info on stdout
./heplify -i eth0 -bpf "port 4789" -hs 192.168.1.1:9060 -l debug -e

# Run heplify in "HEP Collector" mode in order to receive HEP input via TCP on port 9060 and fork (output) to two HEP servers listening on port 9063
./heplify -e -hs HEPServer1:9063,HEPserver2:9063 -hin tcp:1.2.3.4:9060


```
### Made by Humans

This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.

If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)
