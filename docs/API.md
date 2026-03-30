# API Reference

heplify exposes two optional HTTP servers configured independently:

| Server | Config section | Default port | Purpose |
|--------|---------------|-------------|---------|
| API / Web UI | `api_settings` | `9060` | Live stats dashboard, REST endpoints |
| Prometheus | `prometheus_settings` | `9096` | Prometheus `/metrics` scrape endpoint |

---

## API Server (`api_settings`)

### `GET /health`

Returns the current health status of the agent. Always open — no auth required.

**Response** `200 OK` `application/json`

```json
{
  "status": "ok",
  "connected_transports": 1,
  "queue_size": 0,
  "buffer_size_bytes": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` when at least one transport is connected, otherwise `"degraded"` |
| `connected_transports` | int | Number of currently connected HEP transports |
| `queue_size` | int | Current number of packets waiting in the internal queue |
| `buffer_size_bytes` | int | Bytes currently held in the failover buffer |

```
curl http://localhost:9060/health
```

---

### `GET /api/stats`

Returns a full live statistics snapshot. Protected by HTTP Basic Auth when `api_settings.username` is set.

**Response** `200 OK` `application/json`

```json
{
  "node_name": "my-server",
  "node_id": 0,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "interfaces": ["eth0"],
  "capture_modes": {
    "eth0": ["SIP", "RTCP"]
  },
  "uptime_seconds": 3600,
  "uptime": "1h0m0s",
  "packets": {
    "total":      1500,
    "sip":        1200,
    "rtcp":        100,
    "rtcp_fail":    10,
    "rtp":           0,
    "dns":           5,
    "log":           0,
    "hep_sent":   1300,
    "duplicates":    5,
    "unknown":      180
  },
  "transport": [
    {
      "addr":       "homer.example.com:9060",
      "proto":      "tcp",
      "connected":  true,
      "reconnects": 0,
      "sent":       1300,
      "errors":        0
    }
  ]
}
```

#### Top-level fields

| Field | Type | Description |
|-------|------|-------------|
| `node_name` | string | Value of `system_settings.node_name` |
| `node_id` | int | Value of `system_settings.node_id` |
| `uuid` | string | Value of `system_settings.uuid` (auto-generated if empty) |
| `interfaces` | array | Capture interface names |
| `capture_modes` | object | Per-interface list of active capture modes |
| `uptime_seconds` | int | Seconds since agent start |
| `uptime` | string | Human-readable uptime |

#### `packets` object

| Field | Description |
|-------|-------------|
| `total` | Sum of all classified packets (sip + rtcp + rtp + dns + log + duplicates + unknown) |
| `sip` | Packets decoded as SIP |
| `rtcp` | RTCP packets successfully decoded |
| `rtcp_fail` | RTCP packets that failed to decode |
| `rtp` | RTP packets |
| `dns` | DNS packets |
| `log` | Syslog packets |
| `hep_sent` | Packets successfully sent as HEP |
| `duplicates` | Duplicate packets detected and dropped |
| `unknown` | Packets that could not be classified or failed to decode |

#### `transport` array

| Field | Type | Description |
|-------|------|-------------|
| `addr` | string | Remote HEP collector address |
| `proto` | string | Transport protocol (`tcp`, `udp`, `tls`) |
| `connected` | bool | Whether the connection is currently active |
| `reconnects` | int | Number of reconnect attempts since start |
| `sent` | int | Packets successfully sent via this transport |
| `errors` | int | Send errors on this transport |

```
curl -u admin:secret http://localhost:9060/api/stats
```

---

## Prometheus Server (`prometheus_settings`)

### `GET /metrics`

Exposes Prometheus-format metrics for scraping.

Optionally protected by HTTP Basic Auth when `prometheus_settings.auth: true` and `api_settings.username` is set.

**Metrics exposed**

| Metric | Type | Description |
|--------|------|-------------|
| `heplify_packets_total` | counter | Total HEP packets sent |
| `heplify_packets_lost` | counter | Packets lost (send errors) |
| `heplify_queue_size` | gauge | Current internal queue depth |
| `heplify_buffer_size_bytes` | gauge | Current failover buffer size in bytes |
| `heplify_reconnects_total` | counter | Total transport reconnect attempts |
| `heplify_transport_connected` | gauge | `1` if transport is connected, `0` otherwise (labels: `addr`, `proto`) |

```
curl http://localhost:9096/metrics
```

Prometheus `scrape_config` example:

```yaml
scrape_configs:
  - job_name: heplify
    static_configs:
      - targets: ["localhost:9096"]
    # basic_auth:
    #   username: admin
    #   password: secret
```

---

## Configuration reference

### `api_settings`

```json
"api_settings": {
  "active":   true,
  "host":     "0.0.0.0",
  "port":     9060,
  "username": "",
  "password": "",
  "ui_file":  "/usr/share/heplify/index.html"
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `active` | `false` | Enable the API / Web UI server |
| `host` | `0.0.0.0` | Listen address |
| `port` | `9060` | Listen port |
| `username` | `""` | HTTP Basic Auth username (empty = no auth) |
| `password` | `""` | HTTP Basic Auth password |

### `prometheus_settings`

```json
"prometheus_settings": {
  "active": true,
  "host":   "0.0.0.0",
  "port":   9096,
  "auth":   false
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `active` | `false` | Enable the Prometheus metrics server |
| `host` | `0.0.0.0` | Listen address |
| `port` | `9096` | Listen port |
| `auth` | `false` | Protect `/metrics` with HTTP Basic Auth (uses `api_settings` credentials) |

---

## CLI flags

```
-api        :9060        Web stats API server address (empty = disabled)
-api-user   ""           HTTP Basic Auth username for the API server
-api-pass   ""           HTTP Basic Auth password for the API server
-prometheus :9096        Prometheus /metrics server address (empty = disabled)
```
