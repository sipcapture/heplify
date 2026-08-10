# Diameter Capture

heplify 2.x can capture Diameter over TCP and SCTP and forward it as HEP `proto_type=56` (same as Captagent / hepagent).

## Enable

CLI:

```bash
./heplify -i eth0 -m SIPDIAMETER
# or Diameter only:
./heplify -i eth0 -m DIAMETER
```

JSON (`examples/heplify.json`):

```json
"capture_mode": ["SIP", "RTCP", "DIAMETER"],
"protocol": [
  {
    "name": "DIAMETER",
    "min_port": 3868,
    "max_port": 3868,
    "protocol": ["tcp", "sctp"]
  }
]
```

**Important:** with a JSON config, Diameter is enabled by the `protocol[]` entry named `DIAMETER` (port range + `tcp`/`sctp`). That drives BPF and packet dispatch. Put `DIAMETER` in `socket[].capture_mode` as well for clarity / stats; `capture_mode` alone without a matching `protocol[]` row is not enough when using a config file.

## What is sent

- HEP protocol type: **56**
- Payload: JSON with command, app-ID, flags, and AVPs
- Correlation ID: **Session-Id** (AVP 263), or `unknown` if missing

## Notes

- TCP Diameter shares the TCP reassembly path with SIP (Length-framed when version byte is `0x01`).
- SCTP Diameter extracts non-fragmented DATA chunks before parsing.
- Homer UI Protocol Search for Diameter may still need a mapping seed (`hepid=56`); ingest/storage works at the HEP layer.
