# Gap analysis: this tree vs legacy heplify expectations

**Last reviewed:** 2026-04-28 (against current `src/`).

Older notes compared a “simplified” line to full **heplify** and listed missing features. **Most of those gaps are now closed in this repository.** This document tracks what is implemented, what is still absent, and migration notes (e.g. scrape URL / flags vs older deployment guides).

---

## Implemented in this codebase

| Area | Where / how |
|------|-------------|
| **Prometheus** | `-prometheus` (e.g. `:9096`); metrics in `src/apiserver/prometheus.go`, wired from `src/cmd/heplify/main.go`. Not the legacy fixed `:8090` default — address is explicit when enabled. |
| **HEP buffering** | Flags `hep-buffer-activate`, `hep-buffer-file`, `hep-buffer-max-size`, `hep-buffer-debug`; logic in `src/transport/sender.go`. |
| **Deduplication** | `-dd` / config `deduplicate`; LRU in `src/sniffer/sniffer.go`. |
| **Discard filters** | SIP: `-dim`, `-diip`, `-disip`, `-didip`; `SipSettings.Discard*` in `src/config/config.go`. |
| **VLAN / ERSPAN / VXLAN** | `-vlan`, `-erspan`; decode paths in `src/decoder/decoder.go`, layers under `src/decoder/ownlayers/`. |
| **gzip** | Rotated pcap: `-zf` (`PcapSettings`); HEP path may gzip payloads in `src/transport/sender.go`. |
| **HEP wire format** | HEP **v3 binary** chunks via `src/hep/encoder.go` (`Encode`). |

---

## Still missing or intentionally narrow

1. **TLS decryption / “TLS scraping”**  
   No keylog / session secrets / decrypt of mirrored TLS to recover SIP inside TLS. TLS in-tree is for the **HTTP API** (`api_settings` / `-api-tls`), not for passive TLS decode of capture traffic.

2. **Protobuf as HEP or alternate capture encoding**  
   This tree sends **HEP3 binary** only. If a collector or legacy peer required a protobuf framing mode, that is **not** present in `src/hep/`.

3. **Scrape URL vs older docs**  
   `/metrics` is optional and shares the HTTP server with the API when enabled; listen address comes from `-prometheus` / config — there is no fixed default port baked into the binary, so Prometheus `scrape_configs` may need updating when moving from very old examples.

---

## Recommendations

- **Docs / operators:** document `-prometheus`, HEP buffer flags, and scrape auth next to deployment examples so behaviour matches expectations from older heplify guides.
- **Only if product requires it:** invest in TLS decrypt (high complexity, keying material, legal/compliance) or protobuf HEP — both were historically “skip for simplified” for good reason.

---

## Archive: original “NOT in NG” list (obsolete)

The following items were once listed as missing from a simplified fork; **they are no longer accurate for this tree** and are kept only for history: Prometheus, HEP buffering, dedup, `Discard*`, VLAN/ERSPAN/VXLAN, gzip compression as a general capability.
