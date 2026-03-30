# Transport Configuration

heplify supports multiple simultaneous HEP destinations, called **transports**.  
Each capture socket can independently choose which transports to use via `transport_profile`.

---

## `transport[]` — HEP destination list

Each entry describes a single remote HEP server or Arrow Flight endpoint.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Unique identifier, referenced by `socket[].transport_profile` |
| `active` | bool | `false` | Enable/disable this transport without removing it |
| `transport` | string | `"udp"` | Protocol: `udp`, `tcp`, `tls`, `grpc-flight` |
| `host` | string | — | Remote host or IP |
| `port` | int | — | Remote port |
| `password` | string | `""` | HEP node password (sent as HEP chunk 0x000e) |
| `payload_zip` | bool | `false` | Compress HEP payload with zlib |
| `skip_verify` | bool | `false` | Skip TLS certificate verification (TLS only) |
| `keepalive` | int | `0` | TCP keep-alive interval in seconds (0 = off) |
| `max_retries` | int | `0` | Max reconnection attempts (0 = unlimited) |

### Arrow Flight additional fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `stream_name` | string | `""` | Arrow Flight stream name |
| `batch_size` | int | `500` | Records per Arrow batch |
| `flush_interval_ms` | int | `1000` | Flush interval in milliseconds |
| `tls_enabled` | bool | `false` | Enable TLS for gRPC connection |

### Example — dual HEP destination

```json
"transport": [
    {
        "name": "homer-prod",
        "active": true,
        "transport": "tcp",
        "host": "10.0.0.1",
        "port": 9060,
        "password": "myHomerPW"
    },
    {
        "name": "homer-dev",
        "active": true,
        "transport": "udp",
        "host": "10.0.0.2",
        "port": 9060,
        "password": ""
    },
    {
        "name": "arrow-flight",
        "active": false,
        "transport": "grpc-flight",
        "host": "localhost",
        "port": 8815,
        "stream_name": "sip_packets",
        "batch_size": 500,
        "flush_interval_ms": 1000
    }
]
```

---

## `socket[].transport_profile` — per-socket routing

By default (empty `transport_profile`) every socket forwards captured packets to **all active transports**.  
Setting `transport_profile` restricts a socket to a named subset of transports.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `transport_profile` | `[]string` | `[]` | Names of `transport[].name` entries this socket uses. Empty = all active transports. |

### Routing diagram

```
socket[0]  transport_profile: ["homer-prod"]
    └──► Sender A ──► transport: homer-prod

socket[1]  transport_profile: ["homer-prod", "homer-dev"]
    └──► Sender B ──► transport: homer-prod
                  └──► transport: homer-dev

collector_settings  (no profile — uses global sender)
    └──► global Sender ──► all active transports
```

---

## Configuration examples

### Single capture interface → single HEP server (default setup)

```json
"socket": [
    {
        "name": "default",
        "active": true,
        "socket_type": "afpacket",
        "transport_profile": ["hepsocket"],
        "device": "any",
        "capture_mode": ["SIP", "RTCP"]
    }
],
"transport": [
    {
        "name": "hepsocket",
        "active": true,
        "transport": "tcp",
        "host": "127.0.0.1",
        "port": 9060
    }
]
```

### Two interfaces → different HEP servers

```json
"socket": [
    {
        "name": "lan",
        "active": true,
        "device": "eth0",
        "transport_profile": ["homer-prod"],
        "capture_mode": ["SIP", "RTCP"]
    },
    {
        "name": "wan",
        "active": true,
        "device": "eth1",
        "transport_profile": ["homer-prod", "homer-dev"],
        "capture_mode": ["SIP"]
    }
],
"transport": [
    {
        "name": "homer-prod",
        "active": true,
        "transport": "tcp",
        "host": "10.0.0.1",
        "port": 9060
    },
    {
        "name": "homer-dev",
        "active": true,
        "transport": "udp",
        "host": "10.0.0.2",
        "port": 9060
    }
]
```

In this setup:
- Traffic captured on `eth0` is sent **only** to `homer-prod`.
- Traffic captured on `eth1` is mirrored to **both** `homer-prod` and `homer-dev`.

### One interface → all active transports (omit transport_profile)

```json
"socket": [
    {
        "name": "default",
        "active": true,
        "device": "any",
        "transport_profile": [],
        "capture_mode": ["SIP", "RTCP"]
    }
],
"transport": [
    { "name": "homer-prod", "active": true, ... },
    { "name": "homer-dev",  "active": true, ... }
]
```

Both transports receive all captured packets — backward-compatible behaviour.

---

## Buffering (`buffer_settings`)

The buffer is shared per-Sender and protects against temporary network outages.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | `false` | Enable disk-backed packet buffer |
| `file` | string | `hep-buffer.dump` | Buffer file path |
| `max_size_bytes` | int | `104857600` | Maximum buffer size (100 MB) |
| `debug` | bool | `false` | Log buffer read/write operations |

When the network destination is unreachable, packets are spooled to the buffer file and re-sent once the connection is restored.

---

## Related documentation

- [COLLECTOR.md](COLLECTOR.md) — inbound HEP relay (`collector_settings`)
- [API.md](API.md) — REST API and Prometheus endpoints
- [CONFIGURATION.md](CONFIGURATION.md) — full configuration reference
