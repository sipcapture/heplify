# Configuration Reference

`heplify` is configured via a JSON file passed with `-config heplify.json`.  
All sections are optional — omitted fields fall back to their defaults.

If you need pure CLI mode, use `-no-config` to ignore both `-config` and `HEPLIFY_CONFIG`.

For a full CLI/ENV/config key mapping, see [`CLI_ENV_CONFIG_MAPPING.md`](CLI_ENV_CONFIG_MAPPING.md).

---

## Table of Contents

- [socket](#socket)
- [transport](#transport)
- [protocol](#protocol)
- [log\_settings](#log_settings)
- [sip\_settings](#sip_settings)
- [hep\_settings](#hep_settings)
- [rtcp\_settings](#rtcp_settings)
- [system\_settings](#system_settings)
- [prometheus\_settings](#prometheus_settings)
- [api\_settings](#api_settings)
- [debug\_settings](#debug_settings)
- [pcap\_settings](#pcap_settings)
- [buffer\_settings](#buffer_settings)
- [script\_settings](#script_settings)
- [collector\_settings](#collector_settings)

---

## `socket`

Array of capture interfaces. At least one active entry is required for packet sniffing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `""` | Logical name for this socket (used in logs) |
| `active` | bool | `false` | Enable this socket |
| `socket_type` | string | `"afpacket"` | Capture backend: `afpacket` or `pcap` |
| `sequential_processing` | bool | `false` | Process packets sequentially (disables parallelism) |
| `device` | string | `"any"` | Network interface to capture on (`any`, `eth0`, etc.) |
| `promisc` | bool | `true` | Enable promiscuous mode |
| `snap_len` | int | `8192` | Maximum bytes to capture per packet |
| `capture_mode` | []string | `["SIP","RTCP"]` | Protocols to capture. Values: `SIP`, `RTP`, `RTCP`, `DNS`, `LOG`, `HEP` |
| `tcp_reasm` | bool | `false` | Enable TCP stream reassembly |
| `sip_reasm` | bool | `false` | Enable SIP reassembly for fragmented TCP (Skype for Business, Lync) |
| `ipfragments` | bool | `true` | Handle IP fragmented packets |
| `vlan` | bool | `false` | Capture packets with 802.1Q VLAN tags |
| `erspan` | bool | `false` | Capture ERSPAN-encapsulated traffic |
| `vxlan` | bool | `false` | Capture VXLAN-encapsulated traffic |
| `bpf_filter` | string | `""` | Custom BPF filter. Overrides the auto-generated filter from the `protocol` section |
| `fanout_id` | uint16 | `0` | AF_PACKET fanout group ID (for multi-worker capture) |
| `fanout_workers` | int | `0` | Number of AF_PACKET fanout workers. `0` = single worker |
| `buffer_size_mb` | int | `0` | AF_PACKET ring buffer size in MB. `0` = OS default |
| `cpu_limit` | int | `0` | Max CPU cores to use. `0` = no limit |
| `pcap_file` | string | `""` | Read from a pcap file instead of a live interface |

> **Note:** To receive incoming HEP from other agents (collector/proxy mode), use the top-level [`collector_settings`](#collector_settings) section, not `socket`.

**Example:**

```json
"socket": [{
  "name": "main",
  "active": true,
  "socket_type": "afpacket",
  "device": "eth0",
  "promisc": true,
  "tcp_reasm": true,
  "sip_reasm": true,
  "snap_len": 65535,
  "capture_mode": ["SIP", "RTCP"],
  "fanout_workers": 4,
  "bpf_filter": ""
}]
```

---

## `transport`

Array of HEP destinations. Multiple active entries send to all destinations simultaneously.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `""` | Logical name (used in logs) |
| `active` | bool | `false` | Enable this transport |
| `protocol` | string | `"HEPv3"` | HEP version: `HEPv3` or `HEPv2` |
| `host` | string | `""` | Destination hostname or IP address |
| `port` | int | `9060` | Destination port |
| `transport` | string | `"udp"` | Network transport: `udp`, `tcp`, `tls`, `grpc-flight` |
| `password` | string | `""` | HEP authentication password |
| `payload_zip` | bool | `false` | Compress HEP payload with zlib |
| `skip_verify` | bool | `false` | Skip TLS certificate verification |
| `keepalive` | int | `5` | TCP keepalive interval in seconds. `0` = disabled |
| `max_retries` | int | `0` | Max reconnect attempts. `0` = unlimited |

**Arrow Flight additional fields** (when `transport = "grpc-flight"`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls_enabled` | bool | `false` | Enable TLS for gRPC connection |
| `stream_name` | string | `""` | Arrow Flight stream/endpoint name |
| `batch_size` | int | `500` | Number of records per Arrow batch |
| `flush_interval_ms` | int | `1000` | Force flush interval in milliseconds |

**Example:**

```json
"transport": [
  {
    "name": "homer",
    "active": true,
    "protocol": "HEPv3",
    "host": "192.168.1.10",
    "port": 9060,
    "transport": "udp",
    "password": ""
  },
  {
    "name": "arrow",
    "active": false,
    "host": "analytics.example.com",
    "port": 8815,
    "transport": "grpc-flight",
    "stream_name": "sip_packets",
    "batch_size": 500,
    "flush_interval_ms": 1000
  }
]
```

---

## `protocol`

Array of protocol definitions used to auto-generate BPF capture filters and to dispatch decoded packets to the correct handler. The `capture_mode` list in `socket` selects which entries are active.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Protocol identifier referenced in `capture_mode`. Built-in: `SIP`, `RTP`, `RTCP`, `DNS`, `HEP` |
| `min_port` | uint16 | Start of port range for this protocol |
| `max_port` | uint16 | End of port range for this protocol |
| `protocol` | []string | Layer-4 protocols: `udp`, `tcp` |
| `filter` | string | Optional BPF filter template. `$minport`/`$maxport` are substituted automatically |
| `description` | string | Human-readable description |

> **Note:** `LOG` (syslog) mode does not require a `protocol` entry — it starts a dedicated UDP listener on port 514 independently of the BPF capture path.

**Example:**

```json
"protocol": [
  {
    "name": "SIP",
    "min_port": 5060,
    "max_port": 5090,
    "protocol": ["udp", "tcp"],
    "description": "SIP signaling"
  },
  {
    "name": "RTCP",
    "min_port": 1024,
    "max_port": 65535,
    "protocol": ["udp"],
    "description": "RTCP stream analysis"
  }
]
```

---

## `log_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `true` | Enable logging |
| `level` | string | `"error"` | Log level: `debug`, `info`, `warn`, `error` |
| `stdout` | bool | `false` | Write logs to stdout |
| `json` | bool | `false` | Use JSON log format instead of text |
| `log_payload` | bool | `false` | Print SIP payload as plain text in debug logs. Requires `level: "debug"` |

**Example:**

```json
"log_settings": {
  "active": true,
  "level": "debug",
  "stdout": true,
  "json": false,
  "log_payload": true
}
```

---

## `sip_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `deduplicate` | bool | `false` | Drop duplicate SIP packets |
| `discard_methods` | []string | `[]` | Drop SIP packets matching these methods, e.g. `["OPTIONS","NOTIFY"]` |
| `discard_ips` | []string | `[]` | Drop packets matching source **or** destination IP |
| `discard_src_ips` | []string | `[]` | Drop packets matching source IP |
| `discard_dst_ips` | []string | `[]` | Drop packets matching destination IP |

---

## `hep_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replace_token` | bool | `false` | Replace the NodePW in received HEP with the locally configured value (collector mode) |
| `deduplicate` | bool | `false` | Deduplicate HEP packets in collector mode |
| `collect_only_sip` | bool | `false` | In collector mode, drop non-SIP HEP packets (ProtoType ≠ 1) |

---

## `rtcp_settings`

Controls RTCP report processing. When `active` is `false`, captured RTCP packets are discarded without being forwarded via HEP.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `true` | Enable RTCP report processing and forwarding |

**Example:**

```json
"rtcp_settings": {
  "active": true
}
```

> **Note:** When running from CLI flags (without a config file), `rtcp_settings.active` defaults to `true` automatically.

---

## `system_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `node_name` | string | `""` | HEP node name (reported in HEP header) |
| `node_id` | uint32 | `0` | HEP node ID |
| `node_pw` | string | `""` | HEP node password |

---

## `prometheus_settings`

Controls whether the Prometheus `/metrics` endpoint is mounted on the HTTP server.  
The HTTP server itself is controlled by [`api_settings`](#api_settings).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Mount the `/metrics` endpoint (requires `api_settings.active: true`) |
| `auth` | bool | `false` | Protect `/metrics` with HTTP Basic Auth (uses `api_settings` credentials) |
| `carriers` | array | `[]` | Optional static CIDR-to-carrier mapping for SIP Prometheus labels |

When `carriers` is set, SIP request and response metrics include `carrier="<name>"`.
Resolution checks the source IP first, then the destination IP. If neither matches,
the label is `carrier="other"`.

```json
"prometheus_settings": {
  "active": true,
  "carriers": [
    { "name": "telecom-alpha", "cidrs": ["10.1.0.0/16"] },
    { "name": "trunk-beta", "cidrs": ["192.0.2.0/24"] }
  ]
}
```

---

## `api_settings`

HTTP server that serves the web stats dashboard, JSON API and Prometheus metrics.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Start the HTTP server |
| `host` | string | `"0.0.0.0"` | Listen host |
| `port` | int | `8008` | Listen port |
| `username` | string | `""` | HTTP Basic Auth username. Empty = auth disabled |
| `password` | string | `""` | HTTP Basic Auth password |
| `tls` | bool | `false` | Enable HTTPS. Requires `cert_file` and `key_file` |
| `cert_file` | string | `""` | TLS certificate file path |
| `key_file` | string | `""` | TLS private key file path |

The following endpoints are always available when the server is running:

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /` | yes (if set) | Web stats dashboard (auto-refreshes every 3 s) |
| `GET /api/stats` | yes (if set) | Live stats as JSON |
| `GET /health` | no | Health check — returns `{"status":"ok"}` when at least one transport is connected, `{"status":"degraded"}` otherwise |
| `GET /metrics` | see `prometheus_settings.auth` | Prometheus metrics (only when `prometheus_settings.active: true`) |

**Example — web UI only (no Prometheus):**

```json
"prometheus_settings": { "active": false },
"api_settings": {
  "active": true,
  "host": "0.0.0.0",
  "port": 8008,
  "username": "admin",
  "password": "secret"
}
```

**Example — web UI + Prometheus with auth:**

```json
"prometheus_settings": { "active": true, "auth": true },
"api_settings": {
  "active": true,
  "host": "0.0.0.0",
  "port": 8008,
  "username": "admin",
  "password": "secret"
}
```

---

## `debug_settings`

Flags to selectively disable processing subsystems (useful for troubleshooting).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disable_tcp_reassembly` | bool | `false` | Disable TCP stream reassembly |
| `disable_ip_defrag` | bool | `false` | Disable IP defragmentation |

---

## `pcap_settings`

PCAP file writing and replay settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `write_file` | string | `""` | Output directory for captured pcap files. Equivalent to CLI `-wf`. Empty = disabled |
| `rotate_minutes` | int | `60` | Rotate pcap files every N minutes. Equivalent to CLI `-rt` |
| `compress` | bool | `false` | Compress rotated pcap files with gzip. Equivalent to CLI `-zf` |
| `max_speed` | bool | `false` | Replay pcap at maximum speed, ignoring timestamps. Equivalent to CLI `-rs` |
| `loop_count` | int | `1` | Number of pcap replay loops. `0` = infinite. Equivalent to CLI `-lp` |
| `eof_exit` | bool | `false` | Exit when pcap replay reaches end of file. Equivalent to CLI `-eof-exit` |

---

## `buffer_settings`

Offline HEP buffer written to disk when the HEP server is unreachable.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | `false` | Enable disk buffer on connection failure |
| `file` | string | `"hep-buffer.dump"` | Path to the buffer file |
| `max_size` | int64 | `104857600` | Max buffer size in bytes (default 100 MB). `0` = unlimited |
| `debug` | bool | `false` | Enable verbose buffer logging |

---

## `script_settings`

Lua scripting engine for per-packet custom processing and filtering.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable Lua scripting engine |
| `file` | string | `""` | Path to the Lua script file |
| `hep_filter` | string | `""` | Comma-separated HEP ProtoTypes to pass to the script (e.g. `"1,5"` for SIP and RTCP). Empty = all types |

**Example:**

```json
"script_settings": {
  "active": true,
  "file": "/etc/heplify/filter.lua",
  "hep_filter": "1"
}
```

---

## Minimal working configuration

```json
{
  "socket": [{
    "name": "default",
    "active": true,
    "socket_type": "afpacket",
    "device": "any",
    "promisc": true,
    "capture_mode": ["SIP", "RTCP"]
  }],
  "transport": [{
    "name": "homer",
    "active": true,
    "protocol": "HEPv3",
    "host": "192.168.1.10",
    "port": 9060,
    "transport": "udp"
  }],
  "protocol": [
    {
      "name": "SIP",
      "min_port": 5060,
      "max_port": 5090,
      "protocol": ["udp", "tcp"]
    },
    {
      "name": "RTCP",
      "min_port": 1024,
      "max_port": 65535,
      "protocol": ["udp"]
    }
  ],
  "log_settings": {
    "active": true,
    "level": "info",
    "stdout": true
  }
}
```

---

## `collector_settings`

Configures heplify as a HEP relay/proxy. When active, heplify listens for incoming HEP packets from other agents and re-forwards them via the `transport` section.

Equivalent CLI flag: `-hin proto:host:port`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable the HEP collector listener |
| `host` | string | `"0.0.0.0"` | Listen host |
| `port` | int | `9060` | Listen port |
| `proto` | string | `"udp"` | Listen protocol: `udp`, `tcp`, `both`, or `http2` |

**Example:**

```json
"collector_settings": {
  "active": true,
  "host": "0.0.0.0",
  "port": 9060,
  "proto": "udp"
}
```
