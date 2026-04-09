# CLI, ENV, and Config Mapping

This document describes how `heplify` resolves configuration from:

1. CLI flags
2. `HEPLIFY_*` environment variables
3. JSON config file (`heplify.json`)

## Precedence and Behavior

- `-no-config` disables config-file loading completely:
  - ignores `-config`
  - ignores `HEPLIFY_CONFIG`
  - uses CLI-only runtime configuration
- Without `-no-config`:
  - if `-config` is set, that file is loaded
  - otherwise `HEPLIFY_CONFIG` is used as file path fallback
  - `HEPLIFY_*` overrides are applied on top of the loaded file
  - explicitly provided CLI flags override resulting config values

## ENV Naming Rules

- Prefix: `HEPLIFY_`
- Nested objects use `_`, for example:
  - `HEPLIFY_LOG_SETTINGS_LEVEL`
  - `HEPLIFY_API_SETTINGS_TLS`
- Array items use `__<index>__`, for example:
  - `HEPLIFY_SOCKET__0__DEVICE`
  - `HEPLIFY_TRANSPORT__1__HOST`
  - `HEPLIFY_FILTER_INCLUDE__0`

## Main Mapping Examples

| CLI flag | Config key | ENV key |
|---|---|---|
| `-i` | `socket[].device` | `HEPLIFY_SOCKET__N__DEVICE` |
| `-t` | `socket[].socket_type` | `HEPLIFY_SOCKET__N__SOCKET_TYPE` |
| `-s` | `socket[].snap_len` | `HEPLIFY_SOCKET__N__SNAP_LEN` |
| `-b` | `socket[].buffer_size_mb` | `HEPLIFY_SOCKET__N__BUFFER_SIZE_MB` |
| `-promisc` | `socket[].promisc` | `HEPLIFY_SOCKET__N__PROMISC` |
| `-pi` | `socket[].promisc_interfaces` | `HEPLIFY_SOCKET__N__PROMISC_INTERFACES__N` |
| `-bpf` | `socket[].bpf_filter` | `HEPLIFY_SOCKET__N__BPF_FILTER` |
| `-m` | `socket[].capture_mode` | `HEPLIFY_SOCKET__N__CAPTURE_MODE__N` |
| `-vlan` | `socket[].vlan` | `HEPLIFY_SOCKET__N__VLAN` |
| `-erspan` | `socket[].erspan` | `HEPLIFY_SOCKET__N__ERSPAN` |
| `-rf` | `socket[].pcap_file` | `HEPLIFY_SOCKET__N__PCAP_FILE` |
| `-fg` | `socket[].fanout_id` | `HEPLIFY_SOCKET__N__FANOUT_ID` |
| `-fw` | `socket[].fanout_workers` | `HEPLIFY_SOCKET__N__FANOUT_WORKERS` |
| `-tcpassembly` | `socket[].tcp_reasm` | `HEPLIFY_SOCKET__N__TCP_REASM` |
| `-sipassembly` | `socket[].sip_reasm` | `HEPLIFY_SOCKET__N__SIP_REASM` |
| `-ipfragment` | `socket[].ipfragments` | `HEPLIFY_SOCKET__N__IPFRAGMENTS` |
| `-hs` | `transport[]` (rebuild from CLI target list) | `HEPLIFY_TRANSPORT__N__{HOST,PORT,TRANSPORT,...}` |
| `-nt` | `transport[].transport` | `HEPLIFY_TRANSPORT__N__TRANSPORT` |
| `-skipverify` | `transport[].skip_verify` | `HEPLIFY_TRANSPORT__N__SKIP_VERIFY` |
| `-keepalive` | `transport[].keepalive` | `HEPLIFY_TRANSPORT__N__KEEPALIVE` |
| `-tcpsendretries` | `transport[].max_retries` | `HEPLIFY_TRANSPORT__N__MAX_RETRIES` |
| `-hin` | `collector_settings.{active,proto,host,port}` | `HEPLIFY_COLLECTOR_SETTINGS_{ACTIVE,PROTO,HOST,PORT}` |
| `-l` | `log_settings.level` | `HEPLIFY_LOG_SETTINGS_LEVEL` |
| `-S` | `log_settings.stdout` | `HEPLIFY_LOG_SETTINGS_STDOUT` |
| `-log-format` | `log_settings.json` | `HEPLIFY_LOG_SETTINGS_JSON` |
| `-log-payload` | `log_settings.log_payload` | `HEPLIFY_LOG_SETTINGS_LOG_PAYLOAD` |
| `-dd` | `sip_settings.deduplicate` + `hep_settings.deduplicate` | `HEPLIFY_SIP_SETTINGS_DEDUPLICATE` + `HEPLIFY_HEP_SETTINGS_DEDUPLICATE` |
| `-dim` | `sip_settings.discard_methods` | `HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__N` |
| `-diip` | `sip_settings.discard_ips` | `HEPLIFY_SIP_SETTINGS_DISCARD_IPS__N` |
| `-disip` | `sip_settings.discard_src_ips` | `HEPLIFY_SIP_SETTINGS_DISCARD_SRC_IPS__N` |
| `-didip` | `sip_settings.discard_dst_ips` | `HEPLIFY_SIP_SETTINGS_DISCARD_DST_IPS__N` |
| `-fi` | `filter_include` | `HEPLIFY_FILTER_INCLUDE__N` |
| `-di` | `filter_exclude` | `HEPLIFY_FILTER_EXCLUDE__N` |
| `-d` | `debug_selectors` | `HEPLIFY_DEBUG_SELECTORS__N` |
| `-disable-defrag` | `debug_settings.disable_ip_defrag` | `HEPLIFY_DEBUG_SETTINGS_DISABLE_IP_DEFRAG` |
| `-disable-tcp-reasm` | `debug_settings.disable_tcp_reassembly` | `HEPLIFY_DEBUG_SETTINGS_DISABLE_TCP_REASSEMBLY` |
| `-wf` | `pcap_settings.write_file` | `HEPLIFY_PCAP_SETTINGS_WRITE_FILE` |
| `-rt` | `pcap_settings.rotate_minutes` | `HEPLIFY_PCAP_SETTINGS_ROTATE_MINUTES` |
| `-zf` | `pcap_settings.compress` | `HEPLIFY_PCAP_SETTINGS_COMPRESS` |
| `-rs` | `pcap_settings.max_speed` | `HEPLIFY_PCAP_SETTINGS_MAX_SPEED` |
| `-lp` | `pcap_settings.loop_count` | `HEPLIFY_PCAP_SETTINGS_LOOP_COUNT` |
| `-eof-exit` | `pcap_settings.eof_exit` | `HEPLIFY_PCAP_SETTINGS_EOF_EXIT` |
| `-hep-buffer-activate` | `buffer_settings.enable` | `HEPLIFY_BUFFER_SETTINGS_ENABLE` |
| `-hep-buffer-file` | `buffer_settings.file` | `HEPLIFY_BUFFER_SETTINGS_FILE` |
| `-hep-buffer-max-size` | `buffer_settings.max_size` | `HEPLIFY_BUFFER_SETTINGS_MAX_SIZE` |
| `-hep-buffer-debug` | `buffer_settings.debug` | `HEPLIFY_BUFFER_SETTINGS_DEBUG` |
| `-script-file` | `script_settings.file` + `script_settings.active` | `HEPLIFY_SCRIPT_SETTINGS_FILE` + `HEPLIFY_SCRIPT_SETTINGS_ACTIVE` |
| `-script-hep-filter` | `script_settings.hep_filter` | `HEPLIFY_SCRIPT_SETTINGS_HEP_FILTER` |
| `-prometheus` | `prometheus_settings.{active,host,port}` | `HEPLIFY_PROMETHEUS_SETTINGS_{ACTIVE,HOST,PORT}` |
| `-api` | `api_settings.{active,host,port}` | `HEPLIFY_API_SETTINGS_{ACTIVE,HOST,PORT}` |
| `-api-user` | `api_settings.username` | `HEPLIFY_API_SETTINGS_USERNAME` |
| `-api-pass` | `api_settings.password` | `HEPLIFY_API_SETTINGS_PASSWORD` |
| `-api-tls` | `api_settings.tls` | `HEPLIFY_API_SETTINGS_TLS` |
| `-api-cert` | `api_settings.cert_file` | `HEPLIFY_API_SETTINGS_CERT_FILE` |
| `-api-key` | `api_settings.key_file` | `HEPLIFY_API_SETTINGS_KEY_FILE` |
| `-collectonlysip` | `hep_settings.collect_only_sip` | `HEPLIFY_HEP_SETTINGS_COLLECT_ONLY_SIP` |
| `-replacetoken` | `hep_settings.replace_token` | `HEPLIFY_HEP_SETTINGS_REPLACE_TOKEN` |
| `-hi` | `system_settings.node_id` | `HEPLIFY_SYSTEM_SETTINGS_NODE_ID` |
| `-hn` | `system_settings.node_name` | `HEPLIFY_SYSTEM_SETTINGS_NODE_NAME` |
| `-hp` | `system_settings.node_pw` | `HEPLIFY_SYSTEM_SETTINGS_NODE_PW` |

## Notes

- `-no-config` has no `HEPLIFY_*` equivalent by design.
- `HEPLIFY_CONFIG` is only a file-path selector (like implicit `-config`), not a config key override.
- `HEPLIFY_BUFFER_SETTINGS_MAX_SIZE` supports both plain bytes (e.g. `104857600`) and unit suffixes (`KB`, `MB`, `GB`, `TB`), matching CLI behavior.
