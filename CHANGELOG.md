# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
