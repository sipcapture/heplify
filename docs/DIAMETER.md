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
"capture_mode": ["SIP", "DIAMETER"],
"protocol": [
  {
    "name": "DIAMETER",
    "min_port": 3868,
    "max_port": 3868,
    "protocol": ["tcp", "sctp"]
  }
]
```

Default Diameter port is **3868**. Adjust `min_port`/`max_port` if your peers use another port.

## What is sent

- HEP protocol type: **56**
- Payload: JSON with command, app-ID, flags, and AVPs
- Correlation ID: **Session-Id** (AVP 263), or `unknown` if missing

## Notes

- TCP Diameter shares the TCP reassembly path with SIP (Length-framed when version byte is `0x01`).
- SCTP Diameter extracts non-fragmented DATA chunks before parsing.
- Homer UI Protocol Search for Diameter may still need a mapping seed (`hepid=56`); ingest/storage works at the HEP layer.
