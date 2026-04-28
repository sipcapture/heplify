# HEP on-disk buffering

When every configured HEP destination is unreachable or all write attempts fail, **heplify** can persist raw HEP payloads to a local file and **replay** them after a connection comes back. This is optional and controlled by `buffer_settings` / CLI flags.

Implementation: `src/transport/sender.go` (`bufferToFile`, `drainBuffer`, `sendToAll`, `sendToGroup`).

---

## When buffering is used

The sender keeps an in-memory queue (`hepQueue`, capacity 20 000 messages). A worker calls `sendToAll` for each queued HEP frame.

Buffering to disk runs only if **`buffer_settings.enable`** is true (CLI: `-hep-buffer-activate`).

**`bufferToFile` is invoked when:**

1. **No HEP client could send the message** — after the two-phase send (`sendToAll`): all **primary** transports fail, then all **failover-only** transports fail (`sendToGroup` returns false for both). The message is then appended to the buffer file. `heplify_hep_error_count` is incremented with empty transport labels in this path.
2. **A `Write` fails and nothing had succeeded yet for that message** — inside `sendToGroup`, if `conn.Write` returns an error and `sent` is still false, the **original** message (pre–per-client gzip) is passed to `bufferToFile` after `handleWriteError` schedules reconnect.

If buffering is **disabled** in these failure cases, the packet is counted as dropped (`heplify_hep_dropped_count` inside `bufferToFile` when `!bufferEnabled`).

**Not the same as queue overflow:** if `Send` cannot enqueue because `hepQueue` is full, the code increments `heplify_hep_dropped_count` / error counters and **does not** write to the disk buffer (`Send` vs `bufferToFile`).

---

## Configuration

### JSON (`buffer_settings`)

| Field | Type | Default / notes |
|-------|------|-----------------|
| `enable` | bool | `false` — must be true to use on-disk buffering. |
| `file` | string | Path to the buffer file. Default in code if empty: `hep-buffer.dump`. `Validate()` rejects paths containing `..` after `filepath.Clean`. |
| `max_size` | int64 (bytes in struct) | Parsed from human-readable strings on CLI (`100MB`, etc.). If **0** when constructing the sender, it is replaced by **100 MiB** (`NewFromTransports`). While draining/writing, if `max_size > 0` and current file size ≥ limit, new packets are **dropped** (warning log + `heplify_hep_dropped_count`). |
| `debug` | bool | Extra debug logs when appending to the buffer. |

### CLI flags

| Flag | Purpose |
|------|---------|
| `-hep-buffer-activate` | Enable buffering. |
| `-hep-buffer-file` | File path (default `HEP-Buffer.dump`). |
| `-hep-buffer-max-size` | Max file size, e.g. `100MB`, `1GB` (suffix `B`, `KB`, `MB`, `GB`). |
| `-hep-buffer-debug` | Verbose buffer logging. |

---

## On-disk format

Each stored message is **length-prefixed**:

1. **4 bytes** — `uint32` length of the following HEP blob, **big-endian**.
2. **`length` bytes** — raw HEP frame exactly as taken from the queue (same bytes the sniffer would send over the wire for HEP; **not** gzip-wrapped even if a transport uses `payload_zip` for live `Write`).

The file is opened with **`O_APPEND`** so new failures append after existing data.

---

## Replay (`drainBuffer`)

After a **successful** TCP/TLS/UDP dial (`reconnectLoop`), the sender starts **`go drainBuffer(client)`** for that `HEPClient`.

Behaviour:

- **Single flight:** each `Sender` has `drainInProgress` (`atomic.Bool`) so only one `drainBuffer` runs at a time for that sender (`CompareAndSwap`).
- Reads the **whole** buffer file into memory under `Sender.mu`.
- Parses consecutive `uint32` length + payload chunks. Stops if:
  - fewer than 4 bytes remain,
  - declared length exceeds remaining bytes (truncated tail — wait for more data on next drain, or manual fix),
  - **`conn` is nil** (disconnect mid-drain),
  - **`Write` fails** — logs, triggers `handleWriteError`, stops,
  - **`maxDrainBatchMessages` (1000)** sends completed in one run — remaining tail is kept for the next drain.
- Successfully sent prefix is removed: either **`Truncate` to 0** if everything was consumed, or write **`remaining`** to `bufferFile.tmp` and **`Rename`** over the main file (atomic-ish tail retention).
- **`heplify_hep_buffer_size_bytes`** is updated from `Stat` after writes and after truncate/replace.

**Important:** replay writes **`msg` as stored** to `conn`. If the live path applies **gzip per transport** (`payload_zip`), drained messages are still **uncompressed raw HEP**; operators should keep buffer + `payload_zip` behaviour in mind for their collector.

---

## Observability

- Gauge **`heplify_hep_buffer_size_bytes`** — current buffer file size (0 when empty / truncated).
- Counters **`heplify_hep_dropped_count`**, **`heplify_hep_error_count`** — queue full, buffer disabled drops, max-size drops, send failures (see `PROMETHEUS_METRICS.md`).

---

## Operational notes

- Ensure the buffer directory has **enough free disk**; cap size with `max_size` to avoid filling the partition.
- **One buffer file per process** is shared by all HEP transports in that `Sender`; drain uses the **first client that just reconnected** to push data — design assumes a sensible collector topology for your deployment.
- On clean shutdown, the in-memory queue is drained with `sendToAll` (which may again spill to the file if backends are still down).

---

## Related tests

`src/transport/sender_reconnect_test.go` — `TestDrainBufferSingleWorker`, `TestDrainBufferKeepsTailOnPartialSend` (partial send leaves tail in file).
