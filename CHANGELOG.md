# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-19

### Added
- Initial release of heplify-ng
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

[Unreleased]: https://github.com/sipcapture/heplify-ng/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sipcapture/heplify-ng/releases/tag/v1.0.0
