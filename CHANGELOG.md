# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Package checks ([#381](https://github.com/sipcapture/heplify/issues/381))**: new `Package check` workflow and `scripts/check_package.sh` that build the deb/rpm like the release and run static checks on them (contents/modes/owners against an expected list, `lintian`, `rpmlint`, `systemd-analyze verify` on the unit, `shellcheck` on the maintainer scripts). Known lintian/rpmlint findings are listed in `scripts/package/`.

### Changed

- **Service user is `homer:homer`**: the Docker image and the systemd unit now run as `homer:homer`, the user of the other HOMER components, instead of `heplify` / a dynamic user. Mounted output directories must be writable by `homer`.
- **Packaging ([#366](https://github.com/sipcapture/heplify/issues/366))**: the deb/rpm packages now create the `homer` system user (or reuse an existing one) and ship `postinstall`/`preremove`/`postremove` scripts (creates `/var/lib/heplify`, daemon-reload, restart on upgrade, stop and disable on removal, state directory cleanup on purge). The systemd unit runs as `homer:homer` with only `CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`, sandboxing options, `StateDirectory=heplify` as working directory and `After=network-online.target`; `/etc/heplify/heplify.json` is now mode 0640 (`root:homer`). Configurations that write outside `/var/lib/heplify` need a `ReadWritePaths=` drop-in. The unit is now installed to `/usr/lib/systemd/system/heplify.service` (was `/etc/systemd/system/`, which is reserved for local administration); upgrading removes the old file, so move any local edits to a drop-in (`systemctl edit heplify`) beforehand.
- **Docker ([#368](https://github.com/sipcapture/heplify/issues/368))**: the image is now based on Debian 13 (trixie) by default (`--build-arg DEBIAN_RELEASE=bookworm` or any other release still works) and runs as `homer:homer` with `CAP_NET_RAW`/`CAP_NET_BIND_SERVICE` as file capabilities (both in Docker's default set); promiscuous mode needs `--user root --cap-add NET_ADMIN`. Added `.dockerignore`, BuildKit cache mounts, OCI labels and a CI job building the image for trixie and bookworm. `docker/docker-compose.yml` is replaced by `docker/compose.yaml`, which now works from a fresh clone (the missing `./config/` mounts and the obsolete `version:` key are gone); use `docker compose -f docker/compose.yaml up`.

### Fixed

- **Packaging ([#364](https://github.com/sipcapture/heplify/issues/364))**: install the binary to `/usr/bin/heplify` in the deb/rpm packages (was `/usr/local/bin`) and update the shipped systemd unit and init script; fix the file paths in `.goreleaser.yml` and ship the service files there too; make `/etc/init.d/heplify` executable.

## [2.1.0] - 2026-11-06

### Security

- **RTCP XR hang**: an XR block length of `0xFFFF` wrapped to 0 and looped forever on one UDP packet.
- **TCP SIP panic**: a huge `Content-Length` overflowed `int` and panicked on slicing; lengths above 1 MiB are now dropped.
- **WebSocket panic**: a 63-bit frame length overflowed the bounds check and panicked in `make`.
- **Diameter panic**: an unpadded last AVP sliced past the end of the message.
- **HEP collector panic**: fixed-size chunks with a wrong body length (for example 6 bytes, empty body) indexed past the body; vendor chunks are now skipped.
- **HEP length wrap**: packets over 65535 bytes had their 16-bit length fields wrap, so on TCP/TLS the rest of the payload was read as new HEP packets. The payload is now truncated to fit.
- **Lua deadlock**: any script calling `GetHEP*`, `SetHEPField`, `GetRawMessage`, `SetRawMessage` or `HashTable` from `onPacket` deadlocked capture on the first packet. Packet binding and the script call are now atomic, so fanout workers no longer see each other's packets.
- **TCP stream memory**: each reassembled stream buffers at most 1 MiB (SIP, Diameter, HTTP upgrade); WebSocket frames, including ping/pong/close, are consumed one frame at a time instead of dropping the whole buffer.
- **Panic safety**: panics while handling one packet (capture, syslog, collector) are recovered, logged and counted in `heplify_packet_panics_total` instead of killing the process.
- **Collector access control**: `collector_settings.allowed_cidrs` and `auth_token` restrict who may send HEP; new `proto: "tls"`. A warning is logged when the collector is open to anyone.
- **Collector limits**: bounded worker pool (`workers`, queue of 10000), `max_connections`, per-connection `read_timeout_sec`, HTTP/2 body limit (64 KiB) and server timeouts; `Stop()` closes live connections. Re-encoded packets keep the TCP flag, IP TOS and MOS chunks.
- **API server**: read/write/idle timeouts, TLS 1.2 minimum, constant-time password check on hashes, warning for Basic Auth over plain HTTP.
- **HEP transport**: dial and write deadlines, so a stalled collector can no longer block capture; `ca_file`, `cert_file`/`key_file` (mutual TLS) and `server_name` for `tls` and `grpc-flight`; warning when `node_pw` is sent in clear text.
- **Memory limits**: IPv4/IPv6 reassembly holds at most 8192 datagrams and 128 KiB per datagram; overlapping IPv6 fragments drop the datagram (RFC 5722). The dedup cache keys on a 64-bit hash instead of the full payload. RTCP correlation caches hold at most 200k entries; one SDP caches at most 32 media.
- **Files**: buffer and pcap files are created `0600` with `O_NOFOLLOW`, directories `0750`. The buffer drain no longer loses messages appended while it runs. Rotated pcap names are unique, so fanout workers no longer overwrite each other's files.
- **Lua sandbox**: scripts get `base`, `table`, `string`, `math` and the time functions of `os` only; `script_settings.unsafe` restores the full library. Every call is limited by `script_settings.timeout_ms` (default 100 ms); `HashTable` is capped at 100k keys.
- **Tunnel spoofing**: `socket[].tunnel_allowed_sources` drops VXLAN/GRE/ERSPAN/IP-in-IP traffic from unknown outer sources.
- **Logs**: `Authorization` and `Proxy-Authorization` values are masked in payload debug logs; `Logp` strips control characters.
- **Deployment**: the systemd unit runs as a dynamic user with only `CAP_NET_RAW`, `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` and a sandbox; the Docker image runs as user `heplify` with file capabilities. **Note:** promiscuous mode in Docker now needs `--user root --cap-add NET_ADMIN`, and mounted output directories must be writable by the `heplify` user.

### Fixed

- **Pcap replay (`-rf`)** no longer starts a live capture on `any` when fanout workers are configured.
- **Shutdown crash**: stopping AF_PACKET capture no longer segfaults (the ring was unmapped while a worker was reading it); capture goroutines are stopped and awaited first.
- **Pcap replay** flushes TCP streams and IP fragments on packet time and at EOF, so the last messages of a capture are sent; `-eof-exit` shuts down through the normal path instead of `os.Exit`.
- **SIP headers** are parsed per line, case-insensitively and only in the header section: `CONTENT-LENGTH` is found, and `c:` no longer matches inside `Contact`.
- **Compound RTCP**: the first packet is parsed within its own length, so report blocks are not read from the next packet.
- **`payload_zip`**: the buffer drain now compresses too, and drain and send worker no longer interleave writes on one connection. A warning is logged when it is used on a stream transport.

### CI

- Builds move to Go 1.26 (latest patch): Go 1.25 is out of support and its last release, 1.25.14, still has open `net/http`, `crypto/tls`, `crypto/x509` and `html/template` vulnerabilities. `golang.org/x/net` is updated to v0.60.0 and `klauspost/compress` to v1.20.2 for known vulnerabilities. New `govulncheck` and `gosec` jobs, fuzz smoke tests on every PR, a nightly fuzz workflow and Dependabot.

## [2.0.28] - 2026-09-04

### Fixed

- **TCP SIP capture timestamps ([#357](https://github.com/sipcapture/heplify/issues/357))**: preserve each segment's capture timestamp when one TCP reassembly callback contains multiple segments.
- **SDP `a=rtcp:` panic ([#360](https://github.com/sipcapture/heplify/issues/360))**: skip truncated `a=rtcp:<port> IN IPx` lines in `ExtractCID()` instead of slicing past the end of the line.

## [2.0.27] - 2026-08-10

### Fixed

- Docker image build: use `golang:1.25` so `go.mod` (`go 1.25.0`) succeeds (`go mod download` failed on 1.24).

## [2.0.26] - 2026-08-10

### Added

- **Diameter capture**: TCP/SCTP Diameter → HEP `proto_type=56` with Session-Id correlation (`-m DIAMETER` / `SIPDIAMETER` / `SIPRTCPDIAMETER`). See [docs/DIAMETER.md](docs/DIAMETER.md).

## [2.0.22] - 2026-05-19

### Added

- Log `hep_bytes`, `wire_bytes`, and `hep_payload_bytes` when HEP UDP send fails with `message too long` (`EMSGSIZE`).
- CLI flag `-print-out-bad-message` / config `debug_settings.print_out_bad_message` to dump HEP/SIP payload hex (and printable SIP text) on that error.
- Periodic discard of stale incomplete IP fragment flows every minute (restores legacy heplify v1 behaviour; reduces memory growth from never-completed fragments).

### Changed

- Incomplete IP fragment flows are never emitted as HEP; the flush only drops stale state.

## [2.0.17] - 2026-04-28

### Changed

- Bump embedded version to 2.0.17. Refresh `sha256` in `Formula/heplify.rb` after the `heplify_darwin_arm64` artifact for this tag is on GitHub Releases.

## [2.0.16] - 2026-04-28

### Changed

- Bump embedded version to 2.0.16. Refresh `sha256` in `Formula/heplify.rb` once the GitHub release artifact `heplify_darwin_arm64` for this tag is published.

## [2.0.8] - 2026-04-01

### Fixed
- **TCP SIP mid-stream resync**: SIP messages on TCP connections that were
  already established before heplify started (no SYN captured) were silently
  dropped. The assembler now falls through to process `r.Bytes` even when
  `r.Skip != 0`, allowing immediate resynchronisation at the first SIP message
  boundary instead of waiting for the connection to close and reopen.
- **TCP SIP timestamp propagation**: consecutive SIP messages delivered inside
  the same TCP segment all receive the correct capture timestamp. Previously
  `s.ts` was cleared to zero after the first message, making subsequent
  messages in the same buffer appear with epoch time (`cap_ts=01:00:00`).
- **AF_PACKET fanout duplication**: the default `-fw 4` fanout worker count
  combined with a default fanout ID of `0` caused every packet to be received
  by all four workers independently (4× duplication). `Start()` now
  auto-assigns a stable non-zero fanout group ID derived from the process PID
  when `fanout_workers > 1` and no explicit `-fg` value is provided.

### Changed
- **TCP assembler flush interval**: reduced from every 1 s with a −30 s
  window to every 200 ms with a −1 s window. Half-open streams (no SYN) are
  now delivered within ≤1.2 s of the first captured segment instead of up to
  30 s.

### Added
- **Capture timestamp in debug logs**: `Received packet from interface` now
  includes `cap_ts=HH:MM:SS.ffffff` (kernel capture time). `Handling SIP
  packet` now includes `cap_ts` and `lag_ms` (time from capture to SIP
  processing) to help diagnose pipeline latency.

## [1.0.0] - 2026-03-19

### Added
- Initial release of heplify
- Packet sniffing via AF_PACKET (TPACKETv3) and libpcap
- HEP v3 encapsulation and forwarding to HOMER / heplify-server
- HEP collector mode — receive and relay HEP from other agents (UDP/TCP)
- Lua scripting engine for custom packet filtering and processing
- Prometheus metrics exporter
- JSON-based configuration compatible with hepagent.go
- Command-line interface compatible with legacy heplify flags
- SIP, RTCP, RTP, DNS capture modes
- TCP reassembly and SIP-over-TCP support
- VLAN and ERSPAN support
- Packet deduplication
- BPF filter support
- PCAP read/write with rotation and gzip compression
- HEP buffer (disk-backed) on transport failure
- Multi-target HEP transport with automatic reconnect
- TLS transport with optional certificate verification skip
- AF_PACKET fanout (multi-worker) support

[Unreleased]: https://github.com/sipcapture/heplify/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sipcapture/heplify/releases/tag/v1.0.0
