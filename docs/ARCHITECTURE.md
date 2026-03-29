# heplify-ng Architecture

## Overview

`heplify-ng` is a high-performance network packet capture and HEP encapsulation agent written in Go.
It captures SIP, RTCP/RTP, DNS, NG (rtpengine), and LOG traffic, encapsulates packets in HEP v3
format, and forwards them to a monitoring backend (HOMER, GigAPI, or any Arrow Flight server).

It is the successor to `heplify` and `heplify.go`, redesigned for modularity, operational
visibility, and support for modern columnar data transports.

---

## Repository Layout

```
heplify-ng/
├── src/cmd/heplify-ng/     # Entry point: CLI flags, startup, graceful shutdown
├── config/             # Config structs, JSON loader, validation
├── collector/          # HEP relay server (receive → re-encode → forward)
├── decoder/            # Protocol parsers (SIP, RTCP, RTP, DNS, NG, WebSocket)
│   └── ownlayers/      # Custom gopacket layers (VXLAN, ERSPAN, HPERM)
├── dump/               # PCAP writer with rotation and optional compression
├── hep/                # HEP v3 encoder (binary TLV)
├── promstats/          # Prometheus metrics
├── script/             # Lua scripting engine (gopher-lua)
├── sniffer/            # Packet capture, decode loop, protocol dispatch
├── transport/          # HEP sender (TCP/UDP/TLS) and Arrow Flight client
├── docker/             # Dockerfile and docker-compose
├── examples/           # systemd unit file and SysV init script
├── scripts/            # Package build helper (nfpm → deb/rpm)
├── docs/               # Documentation
├── heplify.json       # Default configuration file
├── .goreleaser.yml     # GoReleaser configuration
└── nfpm.yaml           # nfpm package metadata
```

---

## Component Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │                  heplify-ng                  │
                         │                                              │
  ┌──────────────┐       │  ┌───────────┐       ┌─────────────────────┐│
  │  Network IF  │──────▶│  │  Sniffer  │──────▶│    Protocol         ││
  │  (af_packet) │       │  │           │       │    Dispatcher       ││
  └──────────────┘       │  └───────────┘       │  SIP/RTCP/RTP/DNS   ││
                         │                       │  NG/LOG/WebSocket   ││
  ┌──────────────┐       │  ┌───────────┐       └──────────┬──────────┘│
  │  PCAP file   │──────▶│  │  Decoder  │                  │           │
  └──────────────┘       │  │  (layers) │       ┌──────────▼──────────┐│
                         │  └───────────┘       │    Lua Script Engine ││
  ┌──────────────┐       │                       │    (on packet hook) ││
  │  HEP input   │──────▶│  ┌───────────┐       └──────────┬──────────┘│
  │  (Collector) │       │  │ Collector │                  │           │
  └──────────────┘       │  │  Server   │       ┌──────────▼──────────┐│
                         │  └─────┬─────┘       │    HEP v3 Encoder   ││
                         │        │              └──────────┬──────────┘│
                         │        └──────────────────────▶ │           │
                         │                       ┌──────────▼──────────┐│
                         │                       │      Sender         ││
                         │                       │  ┌───────────────┐  ││
                         │                       │  │  HEP clients  │  ││
                         │                       │  │ UDP/TCP/TLS   │  ││
                         │                       │  └───────────────┘  ││
                         │                       │  ┌───────────────┐  ││
                         │                       │  │ Arrow Flight  │  ││
                         │                       │  │  (gRPC/Arrow) │  ││
                         │                       │  └───────────────┘  ││
                         │                       └─────────────────────┘│
                         └──────────────────────────────────────────────┘
```

---

## Components

### 1. Entry Point (`src/cmd/heplify-ng`)

Bootstraps the agent from either:
- **CLI flags** — compatible with legacy `heplify` flag names
- **JSON config file** — full `heplify.json` with multi-socket and multi-transport support

Startup sequence:
1. Parse flags / load config
2. Configure `zerolog` (console or JSON, debug selectors)
3. Start `transport.Sender` — establishes connections to all active transports
4. Start `collector.Server` — begins listening for inbound HEP (optional)
5. Start `promstats` HTTP server (optional)
6. Start `sniffer.Sniffer` — begins packet capture loop
7. Block on OS signals (`SIGINT`, `SIGTERM`, `SIGHUP`)
   - `SIGHUP` triggers Lua script hot-reload
8. Graceful shutdown: drain queues, close connections, stop goroutines

---

### 2. Configuration (`config`)

Parsed from `heplify.json` using `encoding/json`.

**Key top-level sections:**

| Section | Purpose |
|---------|---------|
| `socket[]` | Capture interfaces, PCAP files, or HEP collector settings |
| `transport[]` | Outbound connections (HEP or Arrow Flight) |
| `protocol[]` | Port ranges and BPF filters per protocol |
| `sip_settings` | SIP deduplication, discard methods/IPs, custom headers |
| `rtp_settings` | RTP/RTCP correlation, MOS, E-model parameters |
| `log_settings` | Log file path and level |
| `buffer_settings` | Disk buffer for failed sends |

**`TransportSettings` fields relevant to transport type selection:**

| Field | Values | Effect |
|-------|--------|--------|
| `transport` | `"udp"`, `"tcp"`, `"tls"` | HEP over standard socket |
| `transport` | `"grpc-flight"` | Apache Arrow Flight (gRPC) |
| `max_retries` | `0` = unlimited | Hard reconnect limit for TCP |
| `stream_name` | string | Arrow Flight path descriptor |
| `batch_size` | int | Records per Arrow RecordBatch |
| `flush_interval_ms` | int | Max buffer time before forced flush |

---

### 3. Sniffer (`sniffer`)

The packet capture and decode core.

**Capture backends:**

| Backend | Description |
|---------|-------------|
| `afpacket` | Linux `AF_PACKET` / TPACKETv3 — zero-copy, fanout, multi-CPU |
| `pcap` | libpcap — portable, supports live interfaces and offline `.pcap` files |

**Decode pipeline per packet:**

```
raw bytes
  │
  ▼
gopacket layer decode
  (Ethernet → VLAN → IP/IPv6 → TCP/UDP/SCTP)
  (+ VXLAN, ERSPAN, HPERM custom layers)
  │
  ▼
IP defragmentation (IPv4 and IPv6)
  │
  ▼
TCP reassembly (gopacket/tcpassembly + SIP-aware assembler)
  │
  ▼
WebSocket detection (Upgrade header / WS frame magic bytes)
  → extract SIP payload from WebSocket frames
  │
  ▼
Protocol dispatcher  ──▶  handleSIP()
  by port range           handleRTCP()
  or packet content       handleRTP()
                          handleDNS()
                          handleNG()    (rtpengine bencode)
                          handleLOG()
                          handleHEP()   (collector passthrough)
```

**Filters applied before dispatch:**
- BPF filter on the kernel socket
- IP include/exclude lists (`discard_ips`, `discard_src_ips`, `discard_dst_ips`)
- SIP method discard list (`discard_methods`)
- Generic string include/exclude filters (`-fi` / `-di`)
- Payload deduplication via hash map with TTL

---

### 4. Decoders (`decoder`)

Stateless parsers returning structured data or JSON.

| File | Protocol | Output |
|------|----------|--------|
| `decoder.go` | Packet envelope + SIP extraction | `*Packet` struct |
| `rtcp.go` | RTCP SR, RR, SDES, XR, BYE | JSON + SSRC bytes + MOS×100 |
| `correlator.go` | RTCP correlation helper | SSRC → Call-ID mapping |
| `dns.go` | DNS queries and responses | JSON |
| `ng.go` | rtpengine NG protocol (bencode) | raw payload for HEP type 38 |
| `websocket.go` | WebSocket upgrade + framing | SIP payload extraction |
| `ownlayers/` | VXLAN, ERSPAN, HPERM | gopacket `Layer` implementations |

**RTCP parsing detail:**

| Type | Value | Parsed fields |
|------|-------|---------------|
| SR | 200 | SSRC, NTP timestamps, RTP time, packet/octet counts, RR blocks |
| RR | 201 | SSRC, fraction lost, packets lost, jitter, LSR, DLSR, MOS estimate |
| SDES | 202 | SSRC chunks with CNAME, NAME, EMAIL, PHONE, LOC, TOOL, NOTE, PRIV items |
| BYE | 203 | (type recorded, payload ignored) |
| XR | 207 | VoIP Metrics block (RFC 3611): R-factor, MOSCQ, MOSLQ, jitter buffer |

MOS priority: XR VoIP Metrics MOSCQ > RR-derived estimate from fraction lost.

---

### 5. HEP Encoder (`hep`)

Encodes a `hep.Msg` struct into a binary HEP v3 frame (TLV chunks, big-endian).

**Supported HEP chunks:**

| Chunk | ID | Content |
|-------|-----|---------|
| IP protocol family | 0x0001 | `2` (IPv4) or `10` (IPv6) |
| IP protocol | 0x0002 | `6` TCP, `17` UDP, `132` SCTP |
| Source IP | 0x0003/0x0005 | IPv4 or IPv6 |
| Destination IP | 0x0004/0x0006 | IPv4 or IPv6 |
| Source port | 0x0007 | uint16 |
| Destination port | 0x0008 | uint16 |
| Timestamp (sec) | 0x0009 | uint32 Unix |
| Timestamp (μsec) | 0x000a | uint32 |
| Protocol type | 0x000b | SIP=1, RTCP=5, RTP=32, DNS=53, LOG=100, NG=38, … |
| Capture agent ID | 0x000c | uint32 |
| Keep-alive timer | 0x000d | uint16 |
| Auth key | 0x000e | string |
| Payload | 0x000f | bytes |
| Compressed payload | 0x0010 | gzip bytes |
| VLAN ID | 0x0011 | uint16 |
| Capture agent name | 0x0013 | string |
| Call-ID | 0x0011 | string |
| MOS | 0x0020 | uint16 (value × 100) |

---

### 6. Transport & Sender (`transport`)

The `Sender` manages a heterogeneous pool of `transportClient` objects.
Transport type is determined by the `transport` field in each `TransportSettings` entry.

#### HEP clients (UDP / TCP / TLS)

- Each client runs an independent reconnect loop with exponential backoff
  (initial: 500 ms, max: 30 s)
- Optional hard limit via `max_retries` (0 = unlimited)
- Write errors trigger reconnect; in-flight messages are dropped to the disk buffer
- TCP connections use an 8 KB write buffer and optional SO_KEEPALIVE
- TLS: configurable `skip_verify`, custom cert/key PEM paths

**Disk buffer** (`buffer_settings`):
- On send failure the raw HEP frame is appended to a local file (default `hep-buffer.dump`)
- After successful reconnection, a drain goroutine replays buffered frames in batches of 1000
- Max file size is configurable (default 100 MB)

#### Arrow Flight client

- Activated when `transport = "grpc-flight"`
- **Mutually exclusive with HEP**: if any active Flight client exists,
  `sendHEPWithMOS` converts to `PacketRecord` and calls `SendRecord()` — HEP encoding is skipped
- Each packet is converted to a `PacketRecord` and buffered in memory
- A background `flusher` goroutine sends Arrow `RecordBatch` via `DoPut` either:
  - When buffer reaches `batch_size` records, or
  - After `flush_interval_ms` milliseconds (whichever comes first)
- The Arrow schema:

| Field | Arrow type | Description |
|-------|-----------|-------------|
| `timestamp_us` | `uint64` | Capture time in microseconds since epoch |
| `src_ip` | `utf8` | Source IP address |
| `dst_ip` | `utf8` | Destination IP address |
| `src_port` | `uint16` | Source port |
| `dst_port` | `uint16` | Destination port |
| `ip_protocol` | `uint8` | IP protocol number (6=TCP, 17=UDP) |
| `proto_type` | `uint8` | HEP protocol type (1=SIP, 5=RTCP, …) |
| `payload` | `large_utf8` | Raw packet payload |
| `cid` | `utf8` | Call-ID |
| `node_id` | `uint32` | Capture node ID |
| `node_name` | `utf8` | Capture node name |
| `mos` | `float32` | MOS score (0 if unavailable) |

---

### 7. HEP Collector (`collector`)

Receives inbound HEP v3 over UDP, TCP, or both simultaneously, acting as a
relay/proxy between upstream agents and the monitoring backend.

**Features:**
- Decodes received HEP frames using the `heplify` decoder
- `collect_only_sip`: drops non-SIP proto types before forwarding
- `replace_token`: re-encodes the packet, replacing `NodePW`, `NodeID`, `NodeName`
  with values from the local config — useful for multi-tenant token normalization
- Forwards processed frames through the same `Sender` as locally captured traffic

**Configuration** (per socket entry):
```json
"collector_host": "0.0.0.0",
"collector_port": 9060,
"collector_proto": "udp"
```

---

### 8. Lua Scripting Engine (`script`)

Embeds a `gopher-lua` VM for per-packet custom logic.

**Lifecycle:**
- Script is loaded at startup from the path in `socket[].lua_script`
- `SIGHUP` triggers a hot reload — the VM is replaced atomically without packet loss
- Per-packet call overhead is minimized by reusing the VM across packets

**Exposed Lua API:**

| Function | Description |
|----------|-------------|
| `hep.get_src_ip()` | Returns source IP string |
| `hep.get_dst_ip()` | Returns destination IP string |
| `hep.get_src_port()` | Returns source port number |
| `hep.get_dst_port()` | Returns destination port number |
| `hep.get_payload()` | Returns raw payload string |
| `hep.set_payload(s)` | Replaces payload |
| `hep.get_proto_type()` | Returns HEP protocol type byte |
| `hep.drop()` | Signals the sniffer to discard this packet |

---

### 9. Observability (`promstats`)

Prometheus metrics exposed on a configurable HTTP endpoint (default `:9111/metrics`).

**Key metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `heplify_captured_packets_total` | counter | Packets captured per protocol |
| `heplify_filtered_packets_total` | counter | Packets dropped by filters |
| `heplify_duplicated_packets_total` | counter | Packets dropped by deduplication |
| `heplify_sent_bytes_total` | counter | Bytes sent to HEP server |
| `heplify_send_errors_total` | counter | Failed send attempts |
| `heplify_transport_connected` | gauge | `1` if transport is currently connected |
| `heplify_buffered_packets_total` | counter | Packets written to disk buffer |
| `heplify_lua_errors_total` | counter | Lua execution errors |

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. CAPTURE                                                     │
│                                                                 │
│  af_packet / pcap  ──▶  gopacket layers  ──▶  defrag + reassem │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────┐
│  2. FILTER & DECODE                                             │
│                                                                 │
│  BPF → IP/method filters → dedup → Lua hook                    │
│  SIP: extract headers, Call-ID                                 │
│  RTCP: parse SR/RR/SDES/XR, compute MOS                        │
│  DNS: parse query/response to JSON                             │
│  NG: forward bencode payload as-is (HEP type 38)               │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────┐
│  3. ENCAPSULATE                                                 │
│                                                                 │
│  hep.Encode(Msg) → HEP v3 binary frame (TLV chunks)            │
│  Optionally gzip-compress payload chunk                        │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────┐
│  4. SEND                                                        │
│                                                                 │
│  if Arrow Flight client active:                                 │
│    packet → PacketRecord → buffer → DoPut RecordBatch (gRPC)   │
│  else:                                                          │
│    HEP frame → UDP/TCP/TLS socket                              │
│    on failure → append to disk buffer                          │
│    on reconnect → drain buffer in background                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Transport Mutual Exclusivity

Arrow Flight and HEP transports are mutually exclusive at the **send path** level:

```go
// sniffer/sniffer.go — sendHEPWithMOS()
if s.sender.HasFlightClients() {
    s.sender.SendRecord(transport.PacketRecord{...})
    return
}
// fallthrough: standard HEP encode + send
```

This means a single heplify-ng instance either sends HEP frames (UDP/TCP/TLS) **or**
Arrow RecordBatches (gRPC Flight) — never both simultaneously.
The active mode is determined purely by which transport entries have `active: true`
and `"transport": "grpc-flight"` in the config.

---

## Concurrency Model

| Component | Goroutines |
|-----------|-----------|
| Sniffer (afpacket) | 1 per fanout worker (CPU-affined, configurable `cpu_limit`) |
| TCP reassembler | 1 flusher goroutine |
| Sniffer dispatch | 1 worker pool (configurable `num_workers`) |
| Sender worker | 1 queue consumer goroutine |
| Reconnect loop | 1 per disconnected HEP client |
| Buffer drain | 1 goroutine after reconnect |
| Arrow Flight flusher | 1 per Flight client |
| Collector (TCP) | 1 per accepted connection |
| Prometheus HTTP | 1 net/http server goroutine |

Shared state is protected by `sync.RWMutex` (sender client list) and
`sync.Mutex` (per-client connection state). The send queue is a buffered channel
(`chan []byte`, capacity 20000).

---

## Release & Packaging

| Artifact | Tool | Produced by |
|----------|------|-------------|
| Linux binary | `go build` | `make build` / GoReleaser |
| `.deb` package | nfpm | `scripts/build_package.sh` / GoReleaser |
| `.rpm` package | nfpm | `scripts/build_package.sh` / GoReleaser |
| Docker image | Docker | `docker/Dockerfile` (multi-stage) |
| GitHub Release | GoReleaser | `.github/workflows/release.yml` on `v*` tag |

Systemd unit: `examples/heplify-ng.service`
SysV init: `examples/heplify-ng.init`

---

## Configuration Quick Reference

Minimal `heplify.json` for SIP capture → HOMER:

```json
{
  "socket": [{
    "name": "default",
    "active": true,
    "socket_type": "afpacket",
    "device": "eth0",
    "capture_mode": ["SIP", "RTCP"],
    "transport": { "profile": ["homer"] }
  }],
  "transport": [{
    "name": "homer",
    "active": true,
    "protocol": "HEPv3",
    "host": "homer.example.com",
    "port": 9060,
    "transport": "udp"
  }]
}
```

Minimal config for Arrow Flight → Homer 11 (Homer-Lake) or GigAPI:

```json
{
  "socket": [{
    "name": "default",
    "active": true,
    "socket_type": "afpacket",
    "device": "eth0",
    "capture_mode": ["SIP", "RTCP"],
    "transport": { "profile": ["arrow-flight"] }
  }],
  "transport": [{
    "name": "arrow-flight",
    "active": true,
    "transport": "grpc-flight",
    "host": "homer-lake.example.com",
    "port": 8815,
    "stream_name": "sip_packets",
    "batch_size": 500,
    "flush_interval_ms": 1000,
    "tls_enabled": false
  }]
}
```
