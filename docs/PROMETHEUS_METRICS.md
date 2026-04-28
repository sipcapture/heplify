# Prometheus metrics in heplify

Reference for all metrics registered in `src/apiserver/prometheus.go`, including **carrier** configuration (the `carrier` label on SIP metrics).

Source locations: `src/apiserver/prometheus.go`, packet accounting `src/sniffer/stats.go`, SIP labels `src/sniffer/sip_metrics.go`, HEP transport `src/transport/sender.go`.

---

## Enabling metrics and the HTTP endpoint

- **CLI:** `-prometheus :9096` (empty = metrics disabled).
- **JSON:** `prometheus_settings.active: true`, optional `host` and `port` (after `Validate()`, default host `0.0.0.0` and port `9096` when `port == 0`).
- **HTTP:** `/metrics` is mounted on the same HTTP server as the API (`src/apiserver`) when Prometheus is active. **Pull/scrape** model: Prometheus scrapes the agent; nothing is pushed to Prometheus by default.
- **Auth:** `prometheus_settings.auth: true` enables Basic Auth on `/metrics`; credentials come from `api_settings`. If `username` is empty, a warning is logged and `/metrics` may stay unprotected — see `registerPrometheus` in `prometheus.go`.

---

## `prometheus_settings`: carriers and SIP methods

Relevant fields from `src/config/config.go`:

| Field | Type | Purpose |
|-------|------|---------|
| `active` | bool | Enable metric export and `/metrics`. |
| `host` | string | HTTP listen address (often `0.0.0.0`). |
| `port` | int | TCP port (`0` → `Validate()` sets `9096`). |
| `auth` | bool | Basic Auth on `/metrics`. |
| `carriers` | array of objects | Map IP ranges → carrier name for the `carrier` label. |
| `sip_methods` | array of strings | Extra SIP method names for metric normalization (see below). |

### Carrier: purpose and behaviour

The **`carrier`** label on `heplify_sip_requests_total` and `heplify_sip_responses_total` splits SIP traffic by operator or network zone using the packet’s **source and destination IPs**.

**`carriers[]` entry** (`CarrierSettings`):

| Field | Description |
|-------|-------------|
| `name` | String value used as the `carrier` label in Prometheus. Empty names are ignored. |
| `cidrs` | List of CIDR strings. Invalid entries are **silently skipped** (`net.ParseCIDR` failure). An entry with no valid networks does not participate in matching. |

**`Resolve(srcIP, dstIP)` algorithm** (`sip_metrics.go`):

1. If the resolver is nil or has no entries, the label value is **`other`**.
2. Otherwise, walk `carriers` in config order; find the first match where **source IP** is contained in any carrier’s CIDR.
3. If none, repeat for **destination IP**.
4. If still none, use **`other`**.

Order matters: the first matching network on **src**, else on **dst**, wins.

**Examples:** `examples/carriers.json` and the `prometheus_settings` block in `examples/heplify.json`.

### SIP method extension (`sip_methods`)

For SIP metrics, the method is taken from the request line or from the `CSeq` header and normalized: built-in RFC-style methods (`INVITE`, `ACK`, …) keep their name; anything else becomes **`UNKNOWN`** unless listed in `prometheus_settings.sip_methods`.

Those extra strings (e.g. `PING`, `SERVICE`) are added to the allow-list so they appear as their own `method` label instead of `UNKNOWN`.

Empty method is stored as **`UNKNOWN`**; empty carrier string is stored as **`other`** (`metricLabel` in `prometheus.go`).

### SIP response `status_class`

For responses, class is the first status digit plus `xx` (e.g. `200` → `2xx`, `404` → `4xx`).

---

## Metric summary

| Name | Type | Labels | When it changes |
|------|------|--------|-----------------|
| `heplify_packet_count` | Counter | `type` | Each sniffer stats increment (`Stats.Inc`). |
| `heplify_sip_requests_total` | Counter | `method`, `carrier` | Parsed SIP request (not a response); `carrier` from resolver using `src`/`dst` IP. |
| `heplify_sip_responses_total` | Counter | `status_code`, `status_class`, `method`, `carrier` | Parsed SIP response; `method` from `CSeq` when known or configured. |
| `heplify_hep_sent_count` | Counter | — | One HEP message successfully written by the transport (`IncTransportSent` in `sender.go`). |
| `heplify_hep_error_count` | Counter | — | HEP send error (`IncTransportError`). |
| `heplify_hep_dropped_count` | Counter | — | Packet not accepted into the queue / dropped (queue full, etc. — see `sender.go`). |
| `heplify_hep_reconnect_count` | Counter | `addr`, `proto` | Reconnect attempt toward an HEP server. |
| `heplify_hep_queue_size` | Gauge | — | Current HEP send queue depth. |
| `heplify_hep_buffer_size_bytes` | Gauge | — | On-disk HEP buffer file size in bytes; `0` when unused or empty. |
| `heplify_hep_transport_connected` | Gauge | `addr`, `proto` | `1` if that transport is connected, else `0`. |

### `type` label values for `heplify_packet_count`

Defined in `statPrometheusLabel` (`stats.go`):

| `type` | Meaning |
|--------|---------|
| `sip` | SIP packet |
| `rtcp` | RTCP |
| `rtcp_fail` | RTCP: `CorrelateRTCP` returned `nil` (no correlation) |
| `rtp` | RTP |
| `dns` | DNS |
| `log` | LOG |
| `hep_sent` | Sniffer-side “sent”: after enqueue via HEP `SendNoErr` or after an Arrow Flight record send — **not** the same as `heplify_hep_sent_count` |
| `duplicates` | Duplicate (dedup path) |
| `unknown` | Unknown protocol bucket |

If `packetType` is empty, `IncPacketCount` uses **`unknown`**.

---

## HEP counter semantics

- **`heplify_packet_count{type="hep_sent"}`** increments when the sniffer **hands off** a packet to the sender (HEP queue or Flight). Reflects “submitted for sending”.
- **`heplify_hep_sent_count`** increments on a **successful write** in the transport worker — closer to “actually went out on the wire”.

For loss alerting, combine **`heplify_hep_dropped_count`**, **`heplify_hep_error_count`**, and **`heplify_hep_queue_size`**.

---

## Transport labels (`addr`, `proto`)

Used by `heplify_hep_reconnect_count` and `heplify_hep_transport_connected`. Values come from each active HEP transport’s configured host/port and protocol (`udp` / `tcp` / `tls`, etc. — see your `transport[]` entries and `sender.go`).

---

## Example `scrape_configs` (Prometheus)

```yaml
scrape_configs:
  - job_name: heplify
    static_configs:
      - targets: ["host.example:9096"]
    # basic_auth:
    #   username: "..."
    #   password: "..."
```

Metrics path: `http://<host>:<port>/metrics`.
