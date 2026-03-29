# Testing and Diagnostics

## Local checks

- `make lint` - static checks via `go vet`.
- `make lint-golangci` - extended static checks via `golangci-lint`.
- `make lint-all` - runs both `go vet` and `golangci-lint`.
- `make test` - package tests.
- `make test-race` - race detector run.
- `make test-coverage` - coverage report to `coverage.out`.

## Minimal release gate

Before merge, ensure all commands pass:

1. `make lint`
2. `make lint-golangci`
3. `make test`
4. `make test-race`
5. `make test-coverage`

## Runtime diagnostics

- Prometheus metrics: `http://<host>:<port>/metrics`
- Health endpoint: `http://<host>:<port>/health`
- Recommended key metrics:
  - `heplify_hep_reconnect_count`
  - `heplify_hep_queue_size`
  - `heplify_hep_buffer_size_bytes`
  - `heplify_hep_transport_connected`
