# Web Stats UI

heplify includes a built-in HTTP server that serves a real-time statistics dashboard.  
The UI auto-refreshes every 3 seconds and requires no external dependencies.

## Enabling the UI

Add `api_settings` to your `heplify.json`:

```json
"api_settings": {
    "active": true,
    "host": "0.0.0.0",
    "port": 8008,
    "username": "",
    "password": "",
    "ui_file": ""
}
```

Then open `http://<host>:8008/` in a browser.

## Configuration reference

| Field      | Type   | Default     | Description |
|------------|--------|-------------|-------------|
| `active`   | bool   | `false`     | Enable the HTTP server |
| `host`     | string | `"0.0.0.0"` | Listen address |
| `port`     | int    | `8008`      | Listen port |
| `username` | string | `""`        | HTTP Basic Auth username (leave empty to disable auth) |
| `password` | string | `""`        | HTTP Basic Auth password |
| `ui_file`  | string | `""`        | Path to a custom `index.html` on disk; falls back to the embedded UI when empty or unreadable |

## Endpoints

| Path         | Auth required     | Description |
|--------------|-------------------|-------------|
| `/`          | if credentials set | Web dashboard (HTML) |
| `/api/stats` | if credentials set | Live stats JSON |
| `/health`    | never             | Health check JSON |
| `/metrics`   | see below         | Prometheus metrics (only when `prometheus_settings.active: true`) |

> **Note:** `/health` and `/metrics` (when Prometheus auth is off) are always accessible without credentials — safe for load-balancer probes and Prometheus scrapers.

## Prometheus integration

To also expose `/metrics`, enable both sections:

```json
"prometheus_settings": {
    "active": true,
    "auth": false
},
"api_settings": {
    "active": true,
    "host": "0.0.0.0",
    "port": 8008
}
```

Set `prometheus_settings.auth: true` to require the same Basic Auth credentials for `/metrics`.

> **Requirement:** `prometheus_settings.active: true` requires `api_settings.active: true`.

## HTTP Basic Auth

Set `username` and `password` in `api_settings` to protect `/`, `/api/stats`, and (optionally) `/metrics`:

```json
"api_settings": {
    "active": true,
    "host": "0.0.0.0",
    "port": 8008,
    "username": "admin",
    "password": "changeme"
}
```

Or via CLI flags:

```bash
heplify -prometheus 0.0.0.0:8008 -prometheus-user admin -prometheus-pass changeme
```

## Custom UI file

The embedded `index.html` is packaged at `/usr/share/heplify/index.html` in `.deb`/`.rpm` packages.  
You can replace it with your own file without rebuilding the binary:

```json
"api_settings": {
    "active": true,
    "ui_file": "/usr/share/heplify/index.html"
}
```

The server reads the file on every request, so changes take effect immediately without a restart.

## Dark / Light mode

The UI includes a theme toggle button (☀️ / 🌙) in the top-right corner.  
The selected theme is saved in the browser's `localStorage` and restored on next visit.

## Dashboard sections

### Info cards

| Card | Description |
|------|-------------|
| **Uptime** | Time since heplify started |
| **Node** | Node name, ID, and UUID |
| **Interface** | Captured network interface(s) |
| **Capture mode** | Active protocol names |
| **HEP sent** | Total HEP packets successfully sent |
| **Duplicates** | Packets dropped by the deduplication cache |

### Packet counters

Cumulative counters since startup. `Total` = sum of all rows (including Unknown).

| Row | Description |
|-----|-------------|
| SIP | SIP messages parsed and forwarded |
| RTCP | RTCP reports forwarded |
| RTCP (failed) | RTCP packets that failed to parse |
| RTP | RTP packets (when RTP capture is active) |
| DNS | DNS responses (when DNS capture is active) |
| LOG | Syslog messages (when LOG capture is active) |
| Unknown | Packets captured but not matching any configured protocol |
| **Total** | SIP + RTCP + RTCPFail + RTP + DNS + Log + Duplicates + Unknown |

### Transport

One card per configured HEP destination, showing:

- **Connection status** (green `connected` / red `disconnected`)
- **Protocol** (udp / tcp / tls)
- **Reconnects** — number of reconnection attempts
- **Sent** — HEP packets successfully delivered via this transport
- **Errors** — delivery failures (highlighted in red when > 0)
