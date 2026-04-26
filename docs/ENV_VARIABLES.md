# Environment Variables Reference

Heplify supports full configuration via environment variables. All variables use
the `HEPLIFY_` prefix and are applied **on top of** the JSON config file after it
is parsed, so ENV values always win over file values.

## Naming Convention

```
HEPLIFY_<SECTION>_<FIELD>
```

**Arrays** (slices of structs or strings) use double-underscore `__` as an index
delimiter:

```
HEPLIFY_<SECTION>__<INDEX>__<FIELD>
HEPLIFY_<SECTION>_<FIELD>__<INDEX>
```

Examples:
```
HEPLIFY_TRANSPORT__0__HOST=homer.example.com   # transport[0].host
HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0=OPTIONS # sip_settings.discard_methods[0]
```

Indices are **zero-based** and up to **4** elements (0–4) can be set per array
field. The slice is automatically allocated to the required size.

---

## Table of Contents

1. [socket\[\]](#socket)
2. [transport\[\]](#transport)
3. [protocol\[\]](#protocol)
4. [log\_settings](#log_settings)
5. [sip\_settings](#sip_settings)
6. [hep\_settings](#hep_settings)
7. [rtcp\_settings](#rtcp_settings)
8. [system\_settings](#system_settings)
9. [prometheus\_settings](#prometheus_settings)
10. [api\_settings](#api_settings)
11. [debug\_settings](#debug_settings)
12. [script\_settings](#script_settings)
13. [pcap\_settings](#pcap_settings)
14. [buffer\_settings](#buffer_settings)
15. [collector\_settings](#collector_settings)
16. [filter\_include / filter\_exclude](#filter_include--filter_exclude)
17. [debug\_selectors](#debug_selectors)
18. [Usage Examples](#usage-examples)

---

## socket[]

Capture socket definitions. Up to 5 sockets (indices 0–4).

Replace `__0__` with `__1__`, `__2__`, … for additional sockets.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_SOCKET__0__NAME` | string | Socket name (used in logs) |
| `HEPLIFY_SOCKET__0__ACTIVE` | bool | Enable/disable this socket |
| `HEPLIFY_SOCKET__0__SOCKET_TYPE` | string | `pcap` or `afpacket` |
| `HEPLIFY_SOCKET__0__SEQUENTIAL_PROCESSING` | bool | Process packets sequentially (no worker fan-out) |
| `HEPLIFY_SOCKET__0__TRANSPORT_PROFILE__N` | string | Names of transports to send to (N = 0..4) |
| `HEPLIFY_SOCKET__0__DEVICE` | string | Network interface, e.g. `eth0` or `any` |
| `HEPLIFY_SOCKET__0__PROMISC` | bool | Enable promiscuous mode |
| `HEPLIFY_SOCKET__0__TCP_REASM` | bool | Enable TCP reassembly |
| `HEPLIFY_SOCKET__0__IPFRAGMENTS` | bool | Handle IP fragmentation |
| `HEPLIFY_SOCKET__0__VLAN` | bool | Decode VLAN tags |
| `HEPLIFY_SOCKET__0__ERSPAN` | bool | Decode ERSPAN encapsulation |
| `HEPLIFY_SOCKET__0__VXLAN` | bool | Decode VXLAN encapsulation |
| `HEPLIFY_SOCKET__0__PCAP_FILE` | string | Path to pcap file for replay mode |
| `HEPLIFY_SOCKET__0__SNAP_LEN` | int | Capture snapshot length in bytes |
| `HEPLIFY_SOCKET__0__CAPTURE_MODE__N` | string | Protocol capture modes (N = 0..4), e.g. `SIP`, `RTP`, `RTCP` |
| `HEPLIFY_SOCKET__0__FANOUT_ID` | uint16 | AF_PACKET fanout group ID |
| `HEPLIFY_SOCKET__0__FANOUT_WORKERS` | int | Number of AF_PACKET fanout workers |
| `HEPLIFY_SOCKET__0__BUFFER_SIZE_MB` | int | AF_PACKET ring buffer size in MB |
| `HEPLIFY_SOCKET__0__CPU_LIMIT` | int | Max CPUs to use |
| `HEPLIFY_SOCKET__0__BPF_FILTER` | string | Custom BPF filter expression |
| `HEPLIFY_SOCKET__0__SIP_REASM` | bool | Enable SIP message reassembly |
| `HEPLIFY_SOCKET__0__READ_TIMEOUT_MS` | int | Kernel packet delivery timeout in ms (pcap/afpacket) |
| `HEPLIFY_SOCKET__0__PROMISC_INTERFACES__N` | string | Extra interfaces to set promisc on `any` device (N = 0..4) |

---

## transport[]

HEP destination targets. Up to 5 transports (indices 0–4).

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_TRANSPORT__0__NAME` | string | Transport name (referenced by socket `transport_profile`) |
| `HEPLIFY_TRANSPORT__0__ACTIVE` | bool | Enable/disable this transport |
| `HEPLIFY_TRANSPORT__0__FAILOVER_ONLY` | bool | Use only when all primary transports fail |
| `HEPLIFY_TRANSPORT__0__PROTOCOL` | string | HEP protocol version: `HEPv3` (default) or `HEPv2` |
| `HEPLIFY_TRANSPORT__0__HOST` | string | Destination host/IP |
| `HEPLIFY_TRANSPORT__0__TRANSPORT` | string | Network transport: `udp`, `tcp`, `tls`, `grpc-flight` |
| `HEPLIFY_TRANSPORT__0__PORT` | int | Destination port |
| `HEPLIFY_TRANSPORT__0__PASSWORD` | string | HEP auth password |
| `HEPLIFY_TRANSPORT__0__PAYLOAD_ZIP` | bool | Compress HEP payload with zlib |
| `HEPLIFY_TRANSPORT__0__SKIP_VERIFY` | bool | Skip TLS certificate verification |
| `HEPLIFY_TRANSPORT__0__KEEPALIVE` | int | TCP keep-alive interval in seconds (0 = disabled) |
| `HEPLIFY_TRANSPORT__0__MAX_RETRIES` | int | Max reconnect attempts (0 = unlimited) |
| `HEPLIFY_TRANSPORT__0__TLS_ENABLED` | bool | Enable TLS (for `grpc-flight`) |
| `HEPLIFY_TRANSPORT__0__STREAM_NAME` | string | Arrow Flight stream name |
| `HEPLIFY_TRANSPORT__0__BATCH_SIZE` | int | Arrow Flight batch size |
| `HEPLIFY_TRANSPORT__0__FLUSH_INTERVAL_MS` | int | Arrow Flight flush interval in ms |

---

## protocol[]

Custom port-range to protocol mappings. Up to 5 entries (indices 0–4).

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_PROTOCOL__0__NAME` | string | Protocol name, e.g. `SIP`, `RTP` |
| `HEPLIFY_PROTOCOL__0__FILTER` | string | BPF filter override for this protocol |
| `HEPLIFY_PROTOCOL__0__MIN_PORT` | uint16 | Port range start (inclusive) |
| `HEPLIFY_PROTOCOL__0__MAX_PORT` | uint16 | Port range end (inclusive) |
| `HEPLIFY_PROTOCOL__0__PROTOCOL__N` | string | Network protocols to match (N = 0..4): `udp`, `tcp` |
| `HEPLIFY_PROTOCOL__0__DESCRIPTION` | string | Human-readable description |

---

## log_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_LOG_SETTINGS_ACTIVE` | bool | Enable file/stdout logging |
| `HEPLIFY_LOG_SETTINGS_LEVEL` | string | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `HEPLIFY_LOG_SETTINGS_STDOUT` | bool | Log to stdout |
| `HEPLIFY_LOG_SETTINGS_JSON` | bool | Output logs in JSON format |
| `HEPLIFY_LOG_SETTINGS_LOG_PAYLOAD` | bool | Print SIP payload as plain text in debug logs |

---

## sip_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__N` | string | SIP methods to drop, e.g. `OPTIONS` (N = 0..4) |
| `HEPLIFY_SIP_SETTINGS_DISCARD_IPS__N` | string | Drop packets with this IP as src or dst (N = 0..4) |
| `HEPLIFY_SIP_SETTINGS_DISCARD_SRC_IPS__N` | string | Drop packets from this source IP (N = 0..4) |
| `HEPLIFY_SIP_SETTINGS_DISCARD_DST_IPS__N` | string | Drop packets to this destination IP (N = 0..4) |
| `HEPLIFY_SIP_SETTINGS_DEDUPLICATE` | bool | Drop duplicate SIP packets |

---

## hep_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_HEP_SETTINGS_REPLACE_TOKEN` | bool | Replace HEP auth token when relaying |
| `HEPLIFY_HEP_SETTINGS_DEDUPLICATE` | bool | Drop duplicate HEP packets in collector mode |
| `HEPLIFY_HEP_SETTINGS_COLLECT_ONLY_SIP` | bool | In collector mode forward only SIP HEP type |

---

## rtcp_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_RTCP_SETTINGS_ACTIVE` | bool | Enable RTCP stats capture (default: `true`) |

---

## system_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_SYSTEM_SETTINGS_NODE_NAME` | string | Node name sent in HEP header |
| `HEPLIFY_SYSTEM_SETTINGS_NODE_ID` | uint32 | Numeric node ID sent in HEP header |
| `HEPLIFY_SYSTEM_SETTINGS_NODE_PW` | string | HEP node password (same as `transport[N].password` shortcut) |
| `HEPLIFY_SYSTEM_SETTINGS_UUID` | string | Static UUID override |

---

## prometheus_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_PROMETHEUS_SETTINGS_ACTIVE` | bool | Enable Prometheus metrics endpoint |
| `HEPLIFY_PROMETHEUS_SETTINGS_HOST` | string | Listen host (default: `0.0.0.0`) |
| `HEPLIFY_PROMETHEUS_SETTINGS_PORT` | int | Listen port (default: `9096`) |
| `HEPLIFY_PROMETHEUS_SETTINGS_AUTH` | bool | Enable basic auth on metrics endpoint |
| `HEPLIFY_PROMETHEUS_SETTINGS_CARRIERS` | array | Optional CIDR-to-carrier mapping for SIP metric labels; prefer JSON config for nested arrays |

---

## api_settings

Built-in REST API server.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_API_SETTINGS_ACTIVE` | bool | Enable the API server |
| `HEPLIFY_API_SETTINGS_HOST` | string | Listen host |
| `HEPLIFY_API_SETTINGS_PORT` | int | Listen port |
| `HEPLIFY_API_SETTINGS_USERNAME` | string | Basic auth username |
| `HEPLIFY_API_SETTINGS_PASSWORD` | string | Basic auth password |
| `HEPLIFY_API_SETTINGS_TLS` | bool | Enable HTTPS (requires `cert_file` + `key_file`) |
| `HEPLIFY_API_SETTINGS_CERT_FILE` | string | Path to TLS certificate file |
| `HEPLIFY_API_SETTINGS_KEY_FILE` | string | Path to TLS private key file |

---

## debug_settings

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_DEBUG_SETTINGS_DISABLE_TCP_REASSEMBLY` | bool | Disable TCP stream reassembly |
| `HEPLIFY_DEBUG_SETTINGS_DISABLE_IP_DEFRAG` | bool | Disable IP defragmentation |

---

## script_settings

Lua scripting hook for HEP packet manipulation.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_SCRIPT_SETTINGS_ACTIVE` | bool | Enable Lua scripting |
| `HEPLIFY_SCRIPT_SETTINGS_FILE` | string | Path to Lua script file |
| `HEPLIFY_SCRIPT_SETTINGS_HEP_FILTER` | string | HEP type filter for the script (e.g. `1` for SIP) |

---

## pcap_settings

Controls pcap file writing and replay behaviour.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_PCAP_SETTINGS_WRITE_FILE` | string | Output directory for captured pcap files |
| `HEPLIFY_PCAP_SETTINGS_ROTATE_MINUTES` | int | Pcap rotation interval in minutes |
| `HEPLIFY_PCAP_SETTINGS_COMPRESS` | bool | Gzip-compress rotated pcap files |
| `HEPLIFY_PCAP_SETTINGS_MAX_SPEED` | bool | Replay pcap at maximum speed (ignore timestamps) |
| `HEPLIFY_PCAP_SETTINGS_LOOP_COUNT` | int | Number of replay loops (`0` = infinite) |
| `HEPLIFY_PCAP_SETTINGS_EOF_EXIT` | bool | Exit process when pcap replay reaches EOF |

---

## buffer_settings

Disk-backed HEP send buffer for resilience against collector downtime.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_BUFFER_SETTINGS_ENABLE` | bool | Enable the disk buffer |
| `HEPLIFY_BUFFER_SETTINGS_FILE` | string | Buffer file path (default: `hep-buffer.dump`) |
| `HEPLIFY_BUFFER_SETTINGS_MAX_SIZE` | int64 | Max buffer file size in bytes (default: `104857600` = 100 MB) |
| `HEPLIFY_BUFFER_SETTINGS_DEBUG` | bool | Enable buffer debug logging |

---

## collector_settings

Inbound HEP listener — relay / proxy mode. Other agents send HEP to this
address and heplify re-forwards it via the configured transports.

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_COLLECTOR_SETTINGS_ACTIVE` | bool | Enable the HEP collector listener |
| `HEPLIFY_COLLECTOR_SETTINGS_HOST` | string | Listen host |
| `HEPLIFY_COLLECTOR_SETTINGS_PORT` | int | Listen port |
| `HEPLIFY_COLLECTOR_SETTINGS_PROTO` | string | Protocol: `udp`, `tcp`, `both`, `http2` |

---

## filter_include / filter_exclude

Payload-level packet filtering. Each is a list of up to 5 strings (N = 0..4).

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_FILTER_INCLUDE__N` | string | Pass packet **only if** payload contains ALL listed strings |
| `HEPLIFY_FILTER_EXCLUDE__N` | string | Drop packet if payload contains **any** of the listed strings |

---

## debug_selectors

Fine-grained debug subsystem activation (N = 0..4).

| Variable | Type | Description |
|---|---|---|
| `HEPLIFY_DEBUG_SELECTORS__N` | string | Subsystem to enable debug for: `defrag`, `layer`, `payload`, `rtp`, `rtcp`, `sdp` |

---

## Usage Examples

### Shell / systemd

```bash
# Single HEP destination via UDP
export HEPLIFY_TRANSPORT__0__NAME=homer
export HEPLIFY_TRANSPORT__0__ACTIVE=true
export HEPLIFY_TRANSPORT__0__HOST=homer.example.com
export HEPLIFY_TRANSPORT__0__PORT=9060
export HEPLIFY_TRANSPORT__0__TRANSPORT=udp

# Capture on eth0, SIP + RTP
export HEPLIFY_SOCKET__0__ACTIVE=true
export HEPLIFY_SOCKET__0__DEVICE=eth0
export HEPLIFY_SOCKET__0__CAPTURE_MODE__0=SIP
export HEPLIFY_SOCKET__0__CAPTURE_MODE__1=RTP

# Drop OPTIONS and REGISTER from capture
export HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0=OPTIONS
export HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__1=REGISTER

# Enable debug logging to stdout
export HEPLIFY_LOG_SETTINGS_LEVEL=debug
export HEPLIFY_LOG_SETTINGS_STDOUT=true

./heplify -config /etc/heplify/heplify.json
```

### Docker

```dockerfile
FROM sipcapture/heplify:latest
```

```bash
docker run --rm --net=host \
  -v /etc/heplify/heplify.json:/etc/heplify/heplify.json:ro \
  -e HEPLIFY_TRANSPORT__0__HOST=homer.example.com \
  -e HEPLIFY_TRANSPORT__0__PORT=9060 \
  -e HEPLIFY_TRANSPORT__0__ACTIVE=true \
  -e HEPLIFY_SOCKET__0__ACTIVE=true \
  -e HEPLIFY_SOCKET__0__DEVICE=eth0 \
  -e HEPLIFY_LOG_SETTINGS_LEVEL=info \
  sipcapture/heplify:latest
```

### Docker Compose

```yaml
services:
  heplify:
    image: sipcapture/heplify:latest
    network_mode: host
    volumes:
      - ./heplify.json:/etc/heplify/heplify.json:ro
    environment:
      HEPLIFY_TRANSPORT__0__NAME: homer
      HEPLIFY_TRANSPORT__0__ACTIVE: "true"
      HEPLIFY_TRANSPORT__0__HOST: homer.example.com
      HEPLIFY_TRANSPORT__0__PORT: "9060"
      HEPLIFY_TRANSPORT__0__TRANSPORT: udp
      HEPLIFY_SOCKET__0__ACTIVE: "true"
      HEPLIFY_SOCKET__0__DEVICE: eth0
      HEPLIFY_SOCKET__0__CAPTURE_MODE__0: SIP
      HEPLIFY_SOCKET__0__CAPTURE_MODE__1: RTP
      HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0: OPTIONS
      HEPLIFY_LOG_SETTINGS_LEVEL: info
      HEPLIFY_LOG_SETTINGS_STDOUT: "true"
    restart: unless-stopped
```

### Kubernetes (Deployment)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: heplify
spec:
  selector:
    matchLabels:
      app: heplify
  template:
    metadata:
      labels:
        app: heplify
    spec:
      hostNetwork: true
      containers:
        - name: heplify
          image: sipcapture/heplify:latest
          env:
            - name: HEPLIFY_TRANSPORT__0__NAME
              value: homer
            - name: HEPLIFY_TRANSPORT__0__ACTIVE
              value: "true"
            - name: HEPLIFY_TRANSPORT__0__HOST
              value: homer-svc.monitoring.svc.cluster.local
            - name: HEPLIFY_TRANSPORT__0__PORT
              value: "9060"
            - name: HEPLIFY_TRANSPORT__0__TRANSPORT
              value: tcp
            - name: HEPLIFY_SOCKET__0__ACTIVE
              value: "true"
            - name: HEPLIFY_SOCKET__0__DEVICE
              value: eth0
            - name: HEPLIFY_SOCKET__0__SOCKET_TYPE
              value: afpacket
            - name: HEPLIFY_SOCKET__0__CAPTURE_MODE__0
              value: SIP
            - name: HEPLIFY_SOCKET__0__CAPTURE_MODE__1
              value: RTP
            - name: HEPLIFY_LOG_SETTINGS_LEVEL
              value: warn
            - name: HEPLIFY_LOG_SETTINGS_STDOUT
              value: "true"
            # Pull secrets from a Secret object
            - name: HEPLIFY_TRANSPORT__0__PASSWORD
              valueFrom:
                secretKeyRef:
                  name: heplify-secrets
                  key: hep-password
            - name: HEPLIFY_SYSTEM_SETTINGS_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            capabilities:
              add: ["NET_RAW", "NET_ADMIN"]
          volumeMounts:
            - name: config
              mountPath: /etc/heplify/heplify.json
              subPath: heplify.json
      volumes:
        - name: config
          configMap:
            name: heplify-config
```

### Kubernetes — ConfigMap + Secret pattern

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: heplify-secrets
stringData:
  hep-password: "myS3cret"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: heplify-env
data:
  HEPLIFY_TRANSPORT__0__NAME: homer
  HEPLIFY_TRANSPORT__0__ACTIVE: "true"
  HEPLIFY_TRANSPORT__0__HOST: homer.example.com
  HEPLIFY_TRANSPORT__0__PORT: "9060"
  HEPLIFY_SOCKET__0__ACTIVE: "true"
  HEPLIFY_SOCKET__0__DEVICE: any
  HEPLIFY_LOG_SETTINGS_LEVEL: info
```

```yaml
# In container spec:
envFrom:
  - configMapRef:
      name: heplify-env
env:
  - name: HEPLIFY_TRANSPORT__0__PASSWORD
    valueFrom:
      secretKeyRef:
        name: heplify-secrets
        key: hep-password
```

### Failover transport

Primary → Homer1, failover → Homer2.

```bash
export HEPLIFY_TRANSPORT__0__NAME=homer1
export HEPLIFY_TRANSPORT__0__ACTIVE=true
export HEPLIFY_TRANSPORT__0__HOST=homer1.example.com
export HEPLIFY_TRANSPORT__0__PORT=9060

export HEPLIFY_TRANSPORT__1__NAME=homer2
export HEPLIFY_TRANSPORT__1__ACTIVE=true
export HEPLIFY_TRANSPORT__1__FAILOVER_ONLY=true
export HEPLIFY_TRANSPORT__1__HOST=homer2.example.com
export HEPLIFY_TRANSPORT__1__PORT=9060
```

### TLS transport

```bash
export HEPLIFY_TRANSPORT__0__TRANSPORT=tls
export HEPLIFY_TRANSPORT__0__SKIP_VERIFY=false   # verify server cert
```

### Prometheus + API server

```bash
export HEPLIFY_PROMETHEUS_SETTINGS_ACTIVE=true
export HEPLIFY_PROMETHEUS_SETTINGS_PORT=9096

export HEPLIFY_API_SETTINGS_ACTIVE=true
export HEPLIFY_API_SETTINGS_HOST=0.0.0.0
export HEPLIFY_API_SETTINGS_PORT=8080
export HEPLIFY_API_SETTINGS_USERNAME=admin
export HEPLIFY_API_SETTINGS_PASSWORD=secret
```

### HEP relay / collector mode

Accept HEP on UDP 9060 and forward to Homer.

```bash
export HEPLIFY_COLLECTOR_SETTINGS_ACTIVE=true
export HEPLIFY_COLLECTOR_SETTINGS_HOST=0.0.0.0
export HEPLIFY_COLLECTOR_SETTINGS_PORT=9060
export HEPLIFY_COLLECTOR_SETTINGS_PROTO=udp

export HEPLIFY_TRANSPORT__0__ACTIVE=true
export HEPLIFY_TRANSPORT__0__HOST=homer.example.com
export HEPLIFY_TRANSPORT__0__PORT=9060
```

### Pcap replay

```bash
export HEPLIFY_SOCKET__0__ACTIVE=true
export HEPLIFY_SOCKET__0__PCAP_FILE=/recordings/traffic.pcap
export HEPLIFY_PCAP_SETTINGS_MAX_SPEED=true
export HEPLIFY_PCAP_SETTINGS_EOF_EXIT=true
```

### Disk buffer for resilience

```bash
export HEPLIFY_BUFFER_SETTINGS_ENABLE=true
export HEPLIFY_BUFFER_SETTINGS_FILE=/var/lib/heplify/hep-buffer.dump
export HEPLIFY_BUFFER_SETTINGS_MAX_SIZE=524288000   # 500 MB
```
