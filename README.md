<a href="https://sipcapture.org"><img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/></a>

<img src="https://github.com/user-attachments/assets/53cedef3-ba54-466b-a7e8-ac38fe75850c">

<img src="https://img.shields.io/docker/pulls/sipcapture/heplify">

**heplify** is captagent's little brother, optimized for speed and simplicity. It's a single binary which you can run
on Linux, macOS and Windows to capture IPv4 or IPv6 packets and send them to Homer. Heplify can send
SIP, correlated RTCP, DNS, Diameter and Logs into homer.
It handles fragmented and duplicate packets out of the box.

## Platform Support

| OS | Architecture | Capture method |
|---|---|---|
| Linux | amd64, arm64 | AF_PACKET (default), libpcap |
| macOS | arm64 (Apple Silicon) | libpcap |
| Windows | amd64 | [Npcap](https://npcap.com/) |

## What's new in v2

- **JSON configuration file** — all parameters in a single `heplify.json`, no need to pass dozens of flags
- **Multiple HEP transports** — simultaneously forward to multiple destinations (UDP, TCP, TLS, Apache Arrow Flight)
- **Structured logging** — zerolog-based, supports JSON format (`-log-format=json`) and stdout (`-S`)
- **Dynamic BPF filter** — automatically generates kernel-level BPF filters from configured port ranges, reducing CPU load
- **SIP payload logging** — `log_payload` option to print plain-text SIP payloads to log output
- **Arrow Flight transport** — high-performance columnar data delivery over gRPC
- **Improved IP defragmentation** — rewritten IPv4/IPv6 defragmenter with test coverage
- **TCP SIP reassembly** — improved handling of fragmented SIP over TCP (Skype for Business, Lync)
- **HEP mirror / fan-out** — send the same capture to multiple HEP servers (`transport[]` or comma-separated `-hs`); see [docs/TRANSPORT.md](docs/TRANSPORT.md) and [examples/heplify-mirror.json](examples/heplify-mirror.json)
- **Diameter capture** — TCP/SCTP Diameter → HEP `proto_type=56` with Session-Id correlation; see [docs/DIAMETER.md](docs/DIAMETER.md)
- **HEP Collector** — receive HEP from other agents and forward/fan-out to multiple destinations
- **Prometheus metrics** — built-in exporter for agent performance and traffic statistics
- **Web stats dashboard** — live `/` UI showing uptime, interfaces, packet counters and transport status; JSON API at `/api/stats`; optional HTTP Basic Auth
- **Lua scripting engine** — custom per-packet processing, filtering and field manipulation
- **Packet deduplication** — suppresses duplicate packets at the capture layer

---

## Requirements

### Linux

None if you use the binary from the [releases](https://github.com/sipcapture/heplify/releases).

### macOS

None if you use the binary from the [releases](https://github.com/sipcapture/heplify/releases).

> **Note:** Live packet capture requires root or granting capture permissions:
> ```bash
> sudo ./heplify_darwin_arm64 -config heplify.json
> ```

### Windows

Install [Npcap](https://npcap.com/#download) before running heplify (required for packet capture).

## Installation

### Linux

Download [heplify](https://github.com/sipcapture/heplify/releases) and run:

```bash
chmod +x heplify_linux_amd64
./heplify_linux_amd64 -config heplify.json
```

### Linux packages (Debian, Ubuntu, RHEL and derivatives)

Each [release](https://github.com/sipcapture/heplify/releases) provides `.deb` and `.rpm` packages for `amd64` and `arm64`. The `.deb` uses the system libraries (it depends on `libc6` and `libpcap0.8`, installed automatically by `apt`) and requires Debian 12+ or Ubuntu 22.04+; on older systems use the static binary from the same page. The `.rpm` contains a statically linked binary, so it has no library dependencies.

```bash
VERSION=2.0.28   # the release to install, see the releases page
ARCH=amd64       # or arm64

# Debian / Ubuntu
curl -fsSLO "https://github.com/sipcapture/heplify/releases/download/${VERSION}/heplify_${VERSION}_${ARCH}.deb"
sudo apt install "./heplify_${VERSION}_${ARCH}.deb"

# RHEL / Rocky / Alma / Fedora
curl -fsSLO "https://github.com/sipcapture/heplify/releases/download/${VERSION}/heplify_${VERSION}_${ARCH}.rpm"
sudo dnf install "./heplify_${VERSION}_${ARCH}.rpm"
```

The package installs:

| Path | Content |
|------|---------|
| `/usr/bin/heplify` | the binary |
| `/etc/heplify/heplify.json` | configuration (kept on upgrade; mode `0640`, owner `root:homer`, as it may contain passwords) |
| `/etc/heplify/example.lua` | example Lua script |
| `/usr/lib/systemd/system/heplify.service` | systemd unit (customize with `systemctl edit heplify`) |
| `/var/lib/heplify` | state directory and working directory (e.g. the HEP buffer file) |

The service runs as the unprivileged `homer:homer` system user, shared with the other HOMER components (created by the package unless it already exists), with only the `CAP_NET_RAW`, `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` capabilities and a sandboxed filesystem.

A fresh install does **not** start the service, so that the default configuration is not run blindly. Edit `/etc/heplify/heplify.json` (at least the `transport` section with your HEP server and the capture `device`), then:

```bash
sudo systemctl enable --now heplify
journalctl -u heplify -f
```

- **Upgrade**: the configuration is preserved and the service is restarted if it was running.
- **Removal**: the service is stopped and disabled. `apt purge heplify` also deletes `/var/lib/heplify`; the `homer` user is kept. `rpm` has no purge, so `/var/lib/heplify` is kept when removing an rpm.
- **Local adjustments** are made with a systemd drop-in (`sudo systemctl edit heplify`), because the service is sandboxed:

  - *Writing outside `/var/lib/heplify`* (for example a pcap output file) is blocked. Allow it with:

    ```ini
    [Service]
    ReadWritePaths=/path/to/dir
    ```

  - *Ports below 1024* (for example a collector or API listening on UDP 514 or TCP 443) fail with `bind: permission denied`, because the service only has `CAP_NET_RAW` and `CAP_NET_ADMIN`. Either use a port of 1024 or above, or grant the capability:

    ```ini
    [Service]
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    ```

  - *Files named in the configuration* (TLS certificates and keys, Lua scripts, pcap files to read) must be readable by the `homer` user and must not be under `/home` or `/root`. For a key owned by another group, add `SupplementaryGroups=<group>` in the drop-in.

### macOS (Apple Silicon)

**Homebrew** (tap lives in this repo):

```bash
brew tap sipcapture/heplify https://github.com/sipcapture/heplify
brew install heplify
```

Or download [heplify](https://github.com/sipcapture/heplify/releases) and run:

```bash
chmod +x heplify_darwin_arm64
sudo ./heplify_darwin_arm64 -config heplify.json
```

The release workflow updates [`Formula/heplify.rb`](Formula/heplify.rb) (Apple Silicon binary only) after each stable release; to do it by hand, run `scripts/update_formula.sh <VERSION>`.

### Windows

1. Install [Npcap](https://npcap.com/#download)
2. Download `heplify_windows_amd64.exe` from [releases](https://github.com/sipcapture/heplify/releases)
3. Run from an Administrator command prompt:

```cmd
heplify_windows_amd64.exe -config heplify.json
```

### Build from source

```bash
# Requires Go 1.26+
git clone https://github.com/sipcapture/heplify.git
cd heplify
make build
```

### Docker

```bash
docker build --no-cache -t sipcapture/heplify:latest -f docker/Dockerfile .
```

The image is based on Debian 13 (trixie) by default; build on another release with
`--build-arg DEBIAN_RELEASE=bookworm` (any release published for both the `golang` and `debian` images works).

The container runs as the unprivileged `homer:homer` user. Capture is enabled by the `NET_RAW` file
capability on the binary, which Docker grants by default. To let heplify switch an interface into
promiscuous mode, run with `--user root --cap-add NET_ADMIN`, or enable promiscuous mode on the host.

A ready-to-use Compose file is provided (it mounts `examples/heplify.json`; edit it first):

```bash
docker compose -f docker/compose.yaml up --build -d
```

```yaml
heplify:
  image: sipcapture/heplify:latest
  cap_add:
    - CAP_NET_ADMIN
    - CAP_NET_RAW
  command: ["-hs", "192.168.1.1:9060", "-m", "SIP", "-dd", "-l", "info", "-S"]
  network_mode: host
  restart: unless-stopped
```

Docker-safe launch notes:

- If the image already defines `ENTRYPOINT` (heplify binary), pass only flag arguments in `command`.
- Do not prefix `command` with `./heplify` in that case.
- Use `-no-config` when you want deterministic CLI-only behavior and to ignore both `-config` and `HEPLIFY_CONFIG`.

```yaml
heplify:
  image: sipcapture/heplify:latest
  cap_add:
    - CAP_NET_ADMIN
    - CAP_NET_RAW
  command:
    - -no-config
    - -e
    - -hs
    - 127.0.0.1:9060
    - -m
    - SIPRTCP
    - -i
    - ens32
    - -l
    - debug
    - -erspan
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
| `protocol` | Port ranges per protocol — drives BPF filter and packet dispatch |
| `log_settings` | Log level, format, stdout, `log_payload` |
| `sip_settings` | SIP method/IP filtering, deduplication |
| `hep_settings` | HEP collector options, deduplication, token replacement |
| `rtcp_settings` | Enable/disable RTCP report processing (`active`) |
| `system_settings` | HEP node name, ID and password |
| `prometheus_settings` | Prometheus `/metrics` endpoint toggle and auth flag |
| `api_settings` | HTTP server: host, port, Basic Auth credentials |
| `debug_settings` | Disable individual subsystems for troubleshooting |
| `pcap_settings` | PCAP write directory, rotation, compression, replay options |
| `buffer_settings` | Disk-based HEP failover buffer |
| `script_settings` | Lua script path and HEP type filter |

All explicitly provided command-line flags override config-file values.
Use `-no-config` to force CLI-only mode and ignore both `-config` and `HEPLIFY_CONFIG`.

CLI/ENV/config mapping reference: [`docs/CLI_ENV_CONFIG_MAPPING.md`](docs/CLI_ENV_CONFIG_MAPPING.md).

---

## Usage

```
Usage: heplify [options]

Config:
  -config string
        Path to JSON config file (explicitly set CLI flags override file values)
  -no-config
        Ignore both -config and HEPLIFY_CONFIG; use CLI settings only
  -version
        Show version and exit

Logging:
  -l string
        Log level [debug, info, warn, error] (default "info")
  -log-format string
        Log format [text|json] (default "text")
  -log-payload
        Print SIP payload as plain text in debug logs
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
  -ipfragment
        Enable IP fragment reassembly
  -bpf string
        Custom BPF filter
  -pr string
        Port range to capture SIP (default "5060-5090")
  -m string
        Capture mode [SIP, SIPDNS, SIPLOG, SIPRTCP, SIPRTP, DIAMETER, SIPDIAMETER, SIPRTCPDIAMETER] (default "SIPRTCP")
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
        Listen address for incoming HEP, format: proto:host:port [udp:0.0.0.0:9060]
  -collectonlysip
        In collector mode, accept only HEP ProtoType=1 (SIP)
  -replacetoken
        Replace NodePW in forwarded HEP packets (collector mode)

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
        Write captured packets to pcap (output directory)
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

Debug:
  -disable-defrag
        Disable IP defragmentation
  -disable-tcp-reasm
        Disable TCP reassembly processing

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

Prometheus metrics:
  -prometheus string
        Listen address for Prometheus /metrics endpoint, e.g. :9096 (empty = disabled)

Web stats API:
  -api string
        Listen address for web stats API and dashboard, e.g. :8008 (empty = disabled)
  -api-user string
        Username for HTTP Basic Auth (empty = no auth)
  -api-pass string
        Password for HTTP Basic Auth
  -api-tls
        Enable HTTPS for web stats API (requires -api-cert and -api-key)
  -api-cert string
        TLS certificate file for web stats API
  -api-key string
        TLS key file for web stats API
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
./heplify -hs 192.168.1.1:9060 -S -log-format=json -l debug

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

# SIP Prometheus metrics include request/response counters.
# Configure prometheus_settings.carriers in JSON config to add low-cardinality carrier labels.

# Web stats dashboard and JSON API on port 8008
./heplify -hs 192.168.1.1:9060 -api :8008

# Web stats dashboard with Basic Auth (http://host:8008/ requires login)
./heplify -hs 192.168.1.1:9060 -api :8008 -api-user admin -api-pass secret

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
