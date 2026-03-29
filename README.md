<a href="https://sipcapture.org"><img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/></a>

<img src="https://github.com/user-attachments/assets/53cedef3-ba54-466b-a7e8-ac38fe75850c">

<img src="https://img.shields.io/docker/pulls/sipcapture/heplify">

**heplify** is captagent's little brother, optimized for speed and simplicity. It's a single binary which you can run
on Linux, ARM, MIPS to capture IPv4 or IPv6 packets and send them to Homer. Heplify can send
SIP, correlated RTCP, RTCPXR, DNS and Logs into homer.
It handles fragmented and duplicate packets out of the box.

## What's new in v2

- **JSON configuration file** — all parameters in a single `heplify.json`, no need to pass dozens of flags
- **Multiple HEP transports** — simultaneously forward to multiple destinations (UDP, TCP, TLS, Apache Arrow Flight)
- **Structured logging** — zerolog-based, supports JSON format (`-log-format=json`) and stdout (`-S`)
- **Dynamic BPF filter** — automatically generates kernel-level BPF filters from configured port ranges, reducing CPU load
- **SIP payload logging** — `log_payload` option to print plain-text SIP payloads to log output
- **Arrow Flight transport** — high-performance columnar data delivery over gRPC
- **Improved IP defragmentation** — rewritten IPv4/IPv6 defragmenter with test coverage
- **TCP SIP reassembly** — improved handling of fragmented SIP over TCP (Skype for Business, Lync)
- **HEP Collector** — receive HEP from other agents and forward/fan-out to multiple destinations
- **Prometheus metrics** — built-in exporter for agent performance and traffic statistics
- **Lua scripting engine** — custom per-packet processing, filtering and field manipulation
- **Packet deduplication** — suppresses duplicate packets at the capture layer

---

## Requirements

### Linux

None if you use the binary from the [releases](https://github.com/sipcapture/heplify/releases).

## Installation

### Linux

Download [heplify](https://github.com/sipcapture/heplify/releases) and run:

```bash
chmod +x heplify
./heplify -config heplify.json
```

### Build from source

```bash
# Requires Go 1.21+
git clone https://github.com/sipcapture/heplify.git
cd heplify
make build
```

### Docker

```bash
docker build --no-cache -t sipcapture/heplify:latest -f docker/Dockerfile .
```

```yaml
heplify:
  image: sipcapture/heplify:latest
  cap_add:
    - CAP_NET_ADMIN
    - CAP_NET_RAW
  command: ./heplify -hs 192.168.1.1:9060 -m SIP -dd -l info -S
  network_mode: host
  restart: unless-stopped
```

---

## Configuration

The recommended way is a JSON config file. Copy and edit the provided `heplify.json`:

```bash
./heplify -config heplify.json
```

Key sections in `heplify.json`:

| Section | Description |
|---------|-------------|
| `socket` | Capture interface, mode, BPF, snap length |
| `transport` | HEP destination(s): host, port, protocol, password |
| `protocol` | Port ranges per protocol (SIP, RTP, etc.) |
| `log_settings` | Log level, format, stdout, file path, `log_payload` |
| `rtp_settings` | RTP/RTCP correlation and stats |
| `http_settings` | Prometheus/HTTP API listener |
| `script_settings` | Lua script path and HEP type filter |

All command-line flags still work and override the config file.

---

## Usage

```
Usage: heplify [options]

Config:
  -config string
        Path to JSON config file (overrides command line flags)
  -version
        Show version and exit

Logging:
  -l, -x value
        Log level [debug, info, warn, error] (default "info")
  -log-format string
        Log format [text|json] (default "text")
  -e    Log to stderr (default)
  -S    Log to stdout

Capture:
  -i string
        Listen on interface (default "any")
  -t string
        Capture type [pcap, afpacket] (default "afpacket")
  -s int
        Snap length (default 8192)
  -b int
        Interface buffer size (MB) (default 32)
  -promisc
        Enable promiscuous mode (default true)
  -bpf string
        Custom BPF filter
  -pr string
        Port range to capture SIP (default "5060-5090")
  -m string
        Capture mode [SIP, SIPDNS, SIPLOG, SIPRTCP, SIPRTP] (default "SIPRTCP")
  -vlan
        Enable VLAN support
  -erspan
        Enable ERSPAN support

HEP server:
  -hs string
        HEP server address, comma-separated for multiple (default "127.0.0.1:9060")
  -hi uint
        HEP node ID (default 2002)
  -hn string
        HEP node name
  -hp string
        HEP node password
  -nt string
        Network type [udp, tcp, tls] (default "udp")
  -skipverify
        Skip TLS certificate verification
  -keepalive uint
        TCP keepalive interval in seconds, 0 to disable (default 5)

HEP Collector (receive HEP from agents):
  -hin string
        Listen address for incoming HEP [udp:0.0.0.0:9060]

Filtering:
  -dd
        Enable packet deduplication
  -dim string
        Discard SIP methods, comma-separated [OPTIONS,NOTIFY]
  -diip string
        Discard packets by source or destination IP
  -disip string
        Discard packets by source IP
  -didip string
        Discard packets by destination IP
  -fi string
        Include: pass packet only if payload contains string
  -di string
        Exclude: drop packet if payload contains string
  -d string
        Debug selectors [defrag,layer,payload,rtp,rtcp,sdp]

PCAP:
  -rf string
        Read from pcap file
  -wf string
        Write to pcap file
  -rt int
        PCAP rotation time in minutes (default 60)
  -zf
        Compress pcap files with gzip
  -rs
        Replay pcap at maximum speed
  -lp int
        PCAP replay loop count, 0 = infinite (default 1)
  -eof-exit
        Exit when pcap replay reaches EOF

AF_PACKET:
  -fg uint
        Fanout group ID for af_packet
  -fw int
        Fanout worker count for af_packet (default 4)

TCP:
  -tcpassembly
        Enable TCP stream reassembly
  -sipassembly
        Enable SIP reassembly for fragmented TCP
  -tcpsendretries int
        Max TCP reconnect attempts, 0 = unlimited

HEP buffer (offline/failover):
  -hep-buffer-activate
        Enable HEP buffer on connection failure
  -hep-buffer-file string
        Buffer file path (default "HEP-Buffer.dump")
  -hep-buffer-max-size string
        Max buffer size [B, KB, MB, GB] (default "100MB")
  -hep-buffer-debug
        Enable buffer debug logging

Lua scripting:
  -script-file string
        Lua script file path
  -script-hep-filter string
        HEP types to pass to Lua script, comma-separated (default "1")

Prometheus:
  -prometheus string
        Prometheus metrics listen address (default ":9096")
```

---

## Examples

```bash
# Capture SIP and RTCP on any interface, send to 127.0.0.1:9060
./heplify

# Use JSON config file
./heplify -config heplify.json

# Capture SIP only, send to 192.168.1.1:9060 via TLS
./heplify -hs 192.168.1.1:9060 -nt tls -m SIP

# Capture SIP with custom port range on eth2
./heplify -i eth2 -pr 6000-6010 -hs 192.168.1.1:9060

# Send to multiple HEP servers simultaneously
./heplify -hs "192.168.1.1:9060,192.168.2.2:9060"

# Deduplicate packets, discard OPTIONS and NOTIFY
./heplify -hs 192.168.1.1:9060 -dd -dim OPTIONS,NOTIFY

# Log to stdout in JSON format at debug level
./heplify -hs 192.168.1.1:9060 -S -log-format=json -x debug

# Enable TCP SIP reassembly (Skype for Business / Lync)
./heplify -hs 192.168.1.1:9060 -tcpassembly -sipassembly

# Capture HPERM-encapsulated SIP on port 7932
./heplify -i eth2 -bpf "port 7932" -hs 192.168.1.1:9060

# Capture VXLAN-encapsulated SIP on port 4789
./heplify -i eth0 -bpf "port 4789" -hs 192.168.1.1:9060

# HEP Collector mode: receive HEP via TCP and forward to two servers
./heplify -hin tcp:0.0.0.0:9060 -hs HEPServer1:9063,HEPServer2:9063 -S

# Read from pcap file and replay at max speed
./heplify -rf capture.pcap -hs 192.168.1.1:9060 -rs

# Export Prometheus metrics on port 9096
./heplify -hs 192.168.1.1:9060 -prometheus :9096

# Use Lua script to filter/modify packets
./heplify -hs 192.168.1.1:9060 -script-file filter.lua -script-hep-filter 1,5
```

---

## Lua Scripting

Place a Lua script at any path and pass it with `-script-file`. The script receives each matching HEP packet and can read or modify fields before forwarding.

```lua
-- example: drop packets from a specific IP
function onPacket(pkt)
    if pkt.SrcIP == "10.0.0.99" then
        return false  -- drop
    end
    return true
end
```

See `example.lua` for a full reference.

---

### Made by Humans

This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons.

If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)
