# Collector

heplify can act as an inbound HEP relay: other agents or HEP-capable devices send packets to heplify, which re-forwards them via `transport[]` to the upstream collector (e.g. Homer).

```
Agent A ──HEP──▶ heplify (collector_settings) ──HEP──▶ transport[] ──▶ Homer
Agent B ──HEP──▶
```

## Configuration

```json
"collector_settings": {
  "active": false,
  "host":   "0.0.0.0",
  "port":   9060,
  "proto":  "udp"
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `active` | `false` | Enable the inbound HEP listener |
| `host` | `0.0.0.0` | Listen address |
| `port` | `9060` | Listen port |
| `proto` | `"udp"` | Transport protocol — see table below |
| `allowed_cidrs` | `[]` | Source IPs or CIDRs allowed to send HEP (UDP, TCP, TLS and HTTP/2). Empty = any source |
| `auth_token` | `""` | When set, every packet's auth key (HEP chunk 0x0e, `node_pw` on the agent) must match; other packets are dropped |
| `cert_file` / `key_file` | `""` | Server certificate and key for `proto: "tls"` |
| `max_connections` | `1024` | Maximum concurrent TCP/TLS connections; extra connections are closed |
| `workers` | `8` | Goroutines that decode and forward received packets. The queue holds 10000 packets; more are dropped |
| `read_timeout_sec` | `60` | Idle timeout for one TCP/TLS connection |

### Supported protocols

| Value | Description |
|-------|-------------|
| `udp` | UDP listener only (default) |
| `tcp` | TCP listener only |
| `both` | UDP and TCP listeners on the same port |
| `http2` | Cleartext HTTP/2 (h2c), endpoint `POST /hep` with `Content-Type: application/octet-stream`. Bodies over 64 KiB get `413` |
| `tls` | TCP with TLS 1.2+; needs `cert_file` and `key_file` |

### Securing the collector

By default the collector accepts HEP from anyone who can reach the port, and
heplify logs a warning at start-up. Anyone who can send packets can inject
fake SIP into Homer. Use at least one of:

```json
"collector_settings": {
  "active": true,
  "host": "0.0.0.0",
  "port": 9061,
  "proto": "tls",
  "cert_file": "/etc/heplify/collector.crt",
  "key_file": "/etc/heplify/collector.key",
  "allowed_cidrs": ["10.0.0.0/8", "192.0.2.15"],
  "auth_token": "change-me"
}
```

The agents then send with `"transport": "tls"` and `system_settings.node_pw`
set to the same token. Over plain UDP/TCP the token travels in clear text, so
combine it with `allowed_cidrs` or TLS.

## CLI flag

```
-hin  proto:host:port    Enable inbound HEP collector, e.g. -hin udp:0.0.0.0:9060
```

## Behaviour

- Received HEP packets are decoded and validated.
- If `hep_settings.collect_only_sip: true`, non-SIP proto types are silently dropped.
- Packets from sources outside `allowed_cidrs`, or with a wrong `auth_token`, are dropped before decoding.
- If `hep_settings.replace_token: true`, the `NodePW` (and optionally `NodeID` / `NodeName`) in each packet is replaced with values from `system_settings` before re-forwarding.
- Re-encoded packets keep the TCP flag, IP TOS and MOS chunks and are sent to all active `transport[]` entries.
