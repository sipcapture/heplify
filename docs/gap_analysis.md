# Gap Analysis: heplify vs heplify

The user requested to check `heplify` features and identify missing capabilities in `heplify`.

## Heplify Features NOT in Heplify-NG

1.  **Prometheus Metrics** (`promstats` package):
    - `heplify` exposes metrics at `:8090` (default).
    - *Action*: Should be added if monitoring is required.

2.  **HEP Buffering** (`hep-buffer-*` flags):
    - To handle network connectivity issues to the HEP server.
    - *Action*: Useful for reliability, but complex to implement quickly.

3.  **TLS Scraping**:
    - `heplify` seems to support inspecting TLS (requires key?).
    - *Action*: Skip for "simplified" version unless explicitly asked.

4.  **VLAN/ERSPAN/VXLAN Support**:
    - `heplify` has specific flags for these.
    - *Action*: `afpacket` in `heplify` might support some naturally, but explicit extraction logic is missing.

5.  **De-duplication** (`dedup` flag):
    - *Action*: Add simple cache-based deduplication if required.

6.  **Advanced Filtering** (`config.Cfg.Discard*`):
    - `heplify` allows discarding based on method, IP, etc.
    - *Action*: We implemented basic port filtering. Advanced filtering could be added.

7.  **Protobuf Support**:
    - `heplify` can send protobuf.
    - *Action*: Probably overkill for "ng".

8.  **Compression** (gzip):
    - *Action*: Good to have for low bandwidth.

## Recommendation

Focus on adding **Prometheus Metrics** as it's a standard requirement for observability.
HEP Buffering and Deduplication are "nice to have".
User goal was "simplified", so avoid bloated features like Protobuf or complex TLS handling for now.

We will proceed by offering to implement Prometheus metrics.
