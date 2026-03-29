# Configuration Reference

`heplify` is configured via a JSON file passed with `-config heplify.json`.  
All sections are optional — omitted fields fall back to their defaults.

---

## Table of Contents

- [socket](#socket)
- [transport](#transport)
- [protocol](#protocol)
- [log_settings](#log_settings)
- [sip_settings](#sip_settings)
- [rtp_settings](#rtp_settings)
- [hep_settings](#hep_settings)
- [system_settings](#system_settings)
- [network_settings](#network_settings)
- [prometheus_settings](#prometheus_settings)
- [http_settings](#http_settings)
- [script_settings](#script_settings)
- [debug_settings](#debug_settings)
- [pcap_settings](#pcap_settings)
- [buffer_settings](#buffer_settings)
- [subscribe_settings](#subscribe_settings)
- [interception_settings](#interception_settings)

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
| `capture_mode` | []string | `["SIP","RTP"]` | Protocols to capture. Values: `SIP`, `RTP`, `RTCP`, `DNS`, `LOG`, `ISUP`, `NGCP`, `RTPPROXY`, `HEP` |
| `tcp_reasm` | bool | `false` | Enable TCP stream reassembly |
| `sip_reasm` | bool | `false` | Enable SIP reassembly for fragmented TCP (Skype for Business, Lync) |
| `ipfragments` | bool | `true` | Handle IP fragmented packets |
| `vlan` | bool | `false` | Capture packets with 802.1Q VLAN tags |
| `erspan` | bool | `false` | Capture ERSPAN-encapsulated traffic |
| `vxlan` | bool | `false` | Capture VXLAN-encapsulated traffic |
| `bpf_filter` | string | `""` | Custom BPF filter string. Overrides auto-generated filter from `protocol` section |
| `fanout_id` | uint16 | `0` | AF_PACKET fanout group ID (for multi-worker capture) |
| `fanout_workers` | int | `0` | Number of AF_PACKET fanout workers. `0` = auto (one per CPU core) |
| `buffer_size_mb` | int | `0` | AF_PACKET ring buffer size in MB. `0` = OS default |
| `cpu_limit` | int | `0` | Max number of CPU cores to use. `0` = no limit |
| `pcap_file` | string | `""` | Read from a pcap file instead of a live interface |
| `collector_host` | string | `"0.0.0.0"` | Listen address for HEP Collector mode |
| `collector_port` | int | `9060` | Listen port for HEP Collector mode |
| `collector_proto` | string | `"udp"` | Protocol for HEP Collector mode: `udp` or `tcp` |

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
| `password` | string | `""` | HEP authentication password (`node_pw`) |
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

Array of protocol definitions used to auto-generate BPF filters. The `capture_mode` in `socket` selects which entries are activated.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Protocol name, referenced in `capture_mode` (e.g. `SIP`, `RTP`) |
| `min_port` | uint16 | Start of port range for this protocol |
| `max_port` | uint16 | End of port range for this protocol |
| `protocol` | []string | Layer-4 protocols: `udp`, `tcp`, `sctp` |
| `filter` | string | BPF filter template. `$minport` and `$maxport` are substituted automatically |
| `description` | string | Human-readable description |

Built-in protocol names: `SIP`, `RTP`, `RTCP`, `NGCP`, `RTPPROXY`, `ISUP`, `HEP`

**Example:**

```json
"protocol": [{
  "name": "SIP",
  "min_port": 5060,
  "max_port": 5090,
  "protocol": ["udp", "tcp"],
  "description": "SIP signaling"
}]
```

---

## `log_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `true` | Enable file logging |
| `timestamp` | bool | `true` | Include timestamp in log lines |
| `level` | string | `"error"` | Log level: `debug`, `info`, `warn`, `error` |
| `path` | string | `"./"` | Directory to write log files |
| `name` | string | `"heplify.log"` | Log file name |
| `stdout` | bool | `false` | Also write logs to stdout |
| `json` | bool | `false` | Use JSON log format instead of text |
| `syslog` | bool | `false` | Send logs to syslog |
| `log_payload` | bool | `false` | Print SIP payload as plain text in debug logs. When enabled, `payload_hex` is suppressed. Requires `level: "debug"` |

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
| `discard_methods` | []string | `[]` | Drop SIP packets by method, e.g. `["OPTIONS","NOTIFY"]` |
| `censored_methods` | []string | `[]` | Replace payload with empty string for these SIP methods |
| `discard_ips` | []string | `[]` | Drop packets matching source **or** destination IP |
| `discard_src_ips` | []string | `[]` | Drop packets matching source IP |
| `discard_dst_ips` | []string | `[]` | Drop packets matching destination IP |
| `aleg_ids` | []string | `[]` | SIP header names to use as A-leg call ID |
| `custom_headers` | []string | `[]` | Extra SIP headers to extract and include in HEP |
| `disconnect_active` | bool | `true` | Emit disconnect events on BYE/CANCEL |
| `encode_hep` | bool | `true` | Encode packets as HEP before forwarding |
| `check_sip_interval` | string | `"30s"` | Interval for SIP session cleanup |
| `num_workers` | int | `4` | Number of parallel SIP processing workers |
| `force_aleg_id` | bool | `false` | Force use of the first `aleg_ids` header as Call-ID |
| `dialog_timeout` | int | `0` | SIP dialog timeout in seconds. `0` = disabled |
| `transaction.call` | bool | `false` | Enable SIP call transaction tracking |
| `transaction.register` | bool | `false` | Enable SIP REGISTER transaction tracking |
| `transaction.call_timeout` | string | `"6h"` | Expire tracked call transactions after this duration |

---

## `rtp_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rtp_stats_active` | bool | `true` | Enable RTP statistics collection |
| `rtcp_stats_active` | bool | `true` | Enable RTCP statistics collection |
| `num_workers` | int | `4` | Number of RTP processing workers |
| `report_media_interval` | string | `"30s"` | Interval between intermediate RTP reports |
| `report_media_timeout` | string | `"120s"` | Inactive stream timeout |
| `final_media_report_timeout` | string | `"3s"` | Delay before final report after stream ends |
| `ignore_final_short_rtp_stream` | bool | `true` | Suppress reports for very short streams |
| `rtp_short_report` | bool | `true` | Send compact RTP reports |
| `nat_mode_active` | bool | `false` | Enable NAT traversal mode |
| `reverse_nat_mode_active` | bool | `false` | Enable reverse NAT mode |
| `ignore_dtmf_active` | bool | `false` | Exclude DTMF RTP packets from stats |
| `video_mos_adaption_active` | bool | `false` | Apply video-specific MOS adaptation |
| `rate_adaption_video_mos` | float | `1.4` | Video MOS rate adaptation factor |
| `wideband_e_model_active` | bool | `false` | Use wideband E-model for MOS calculation |
| `amr_wb_ie` | int | `13` | AMR-WB equipment impairment factor |
| `amr_wb_bpl` | int | `10` | AMR-WB burst packet loss robustness |
| `ephemeral_streams` | bool | `false` | Track short-lived RTP streams |
| `ephemeral_stats` | bool | `false` | Include ephemeral stream stats |
| `ephemeral_report` | bool | `false` | Send reports for ephemeral streams |
| `replace_media_ip` | []object | `[]` | Rewrite media IP addresses. Each entry: `{"match_media_ip": "10.0.0.1", "alias_media_ip": "192.168.1.1"}` |

---

## `hep_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `hepv2_active` | bool | `true` | Accept/process HEPv2 packets |
| `hepv3_active` | bool | `true` | Accept/process HEPv3 packets |
| `deduplicate` | bool | `false` | Deduplicate HEP packets in collector mode |
| `replace_token` | bool | `false` | Replace NodePW in received HEP with configured value (collector mode) |
| `replace_cid` | bool | `false` | Replace Call-ID in HEP with internal correlation ID |
| `collect_only_sip` | bool | `false` | In collector mode, drop non-SIP HEP packets (ProtoType ≠ 1) |

---

## `system_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `hostname` | string | `""` | Override system hostname reported in HEP |
| `node_name` | string | `"node"` | HEP node name |
| `node_id` | uint32 | `0` | HEP node ID |
| `node_pw` | string | `""` | HEP node password |
| `daemon` | bool | `false` | Run as background daemon |
| `pid_file` | string | `"/var/run/heplify.pid"` | PID file path (daemon mode) |
| `uuid_on_start` | bool | `true` | Generate a new UUID at startup |
| `uuid` | string | `""` | Static UUID (overrides `uuid_on_start`) |
| `fragment_full_search` | bool | `false` | Search full packet for IP fragments |
| `ip_defrag_original` | bool | `false` | Preserve original fragment ordering in defrag |
| `tcp_reasm_v2` | bool | `false` | Use v2 TCP reassembly engine |
| `validate_snaplen` | bool | `false` | Warn when packets exceed snap length |
| `tcpreasm.debug` | bool | `false` | Enable verbose TCP reassembly logging |
| `tcpreasm.clean_timeout` | string | `"120s"` | Remove idle TCP streams after this duration |
| `tcpreasm.fragment_timeout` | string | `"60s"` | Expire incomplete TCP fragments after this duration |
| `pprof.active` | bool | `false` | Enable Go pprof profiling endpoint |
| `pprof.url` | string | `"localhost:6060"` | pprof HTTP listen address |

**Queue sizes** (`system_settings.queue`):

| Field | Default | Description |
|-------|---------|-------------|
| `hep_queue_size` | `10000` | HEP outbound queue depth |
| `sip_process_queue_size` | `10000` | SIP processing queue depth |
| `rtp_packet_queue_size` | `10000` | RTP packet queue depth |
| `rtcp_packet_queue_size` | `10000` | RTCP packet queue depth |
| `disconnect_queue_size` | `10000` | Disconnect event queue depth |
| `publish_packet_queue_size` | `10000` | Publish (stats) queue depth |
| `interception_queue_size` | `10000` | Interception queue depth |
| `ip_defragmenter` | `5000` | Max concurrent IP fragment streams |
| `tcp_reassembler` | `5000` | Max concurrent TCP reassembly streams |

---

## `network_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `option_checker` | bool | `true` | Validate IP/TCP options during decode |
| `tcp_checksum` | bool | `false` | Verify TCP checksums (disable on offloaded NICs) |
| `promisc_interfaces` | []string | `[]` | Additional interfaces to put in promiscuous mode |

---

## `prometheus_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable Prometheus metrics endpoint |
| `host` | string | `"0.0.0.0"` | Listen host |
| `port` | int | `8008` | Listen port. Metrics served at `http://host:port/metrics` |

---

## `http_settings`

Internal HTTP API server (for management and health checks).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable HTTP API server |
| `host` | string | `"0.0.0.0"` | Listen host |
| `port` | int | `18090` | Listen port |
| `api_prefix` | string | `""` | URL prefix for all API routes |
| `debug` | bool | `false` | Enable verbose HTTP request logging |

---

## `script_settings`

Lua scripting engine for per-packet custom processing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable Lua scripting engine |
| `file` | string | `""` | Path to the Lua script file |
| `hep_filter` | string | `""` | Comma-separated HEP ProtoTypes to pass to script (e.g. `"1,5"` for SIP and RTCP). Empty = all types |

**Example:**

```json
"script_settings": {
  "active": true,
  "file": "/etc/heplify/filter.lua",
  "hep_filter": "1"
}
```

---

## `debug_settings`

Flags to selectively disable processing subsystems (useful for troubleshooting).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disable_rtp_stats` | bool | `false` | Disable RTP statistics computation |
| `disable_sip_stats` | bool | `false` | Disable SIP statistics computation |
| `disable_publish` | bool | `false` | Disable publishing packets to transport |
| `disable_disconnect` | bool | `false` | Disable disconnect event generation |
| `disable_interception` | bool | `false` | Disable lawful interception subsystem |
| `disable_tcp_reassembly` | bool | `false` | Disable TCP reassembly |
| `disable_ip_defrag` | bool | `false` | Disable IP defragmentation |

---

## `pcap_settings`

PCAP file writing and replay settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `write_enable` | bool | `false` | Write captured packets to a pcap file |
| `write_path` | string | `"./"` | Directory for pcap output files |
| `rotate_minutes` | int | `60` | Rotate pcap files every N minutes |
| `compress` | bool | `false` | Compress pcap files with gzip |
| `max_speed` | bool | `false` | Replay pcap file at maximum speed (ignore timestamps) |
| `loop_count` | int | `1` | Number of replay loops. `0` = infinite |
| `eof_exit` | bool | `false` | Exit when pcap replay reaches end of file |

---

## `buffer_settings`

Offline HEP buffer for failover when the HEP server is unreachable.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | `false` | Enable disk buffer on connection failure |
| `file` | string | `"hep-buffer.dump"` | Path to buffer file |
| `max_size` | int64 | `0` | Max buffer size in bytes. `0` = unlimited |
| `debug` | bool | `false` | Enable verbose buffer logging |

---

## `subscribe_settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable subscription/intercept subsystem |

---

## `interception_settings`

Lawful interception subsystem settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `active` | bool | `false` | Enable lawful interception |
| `interval` | string | `"10s"` | Polling interval for interception list updates |
| `stats_interval` | string | `"10m"` | Statistics reporting interval |
| `worker_count` | int | `6` | Number of interception processing workers |
| `max_interceptions` | int | `30` | Maximum concurrent interception sessions |

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
    "capture_mode": ["SIP"]
  }],
  "transport": [{
    "name": "homer",
    "active": true,
    "protocol": "HEPv3",
    "host": "192.168.1.10",
    "port": 9060,
    "transport": "udp"
  }],
  "protocol": [{
    "name": "SIP",
    "min_port": 5060,
    "max_port": 5090,
    "protocol": ["udp", "tcp"]
  }],
  "log_settings": {
    "active": true,
    "level": "info",
    "stdout": true
  }
}
```
