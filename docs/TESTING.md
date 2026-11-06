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

## Package tests

The `Package check` workflow runs on pull requests that touch packaging files
(and on demand). It builds the deb and rpm like the release does, then:

- `scripts/check_package.sh`: lintian, rpmlint, contents, `systemd-analyze verify`, shellcheck.
- `scripts/test_package.sh lifecycle IMAGE PACKAGE [OLD_PACKAGE]`: in a clean
  container (Debian 12/13, Ubuntu 22.04/24.04, Rocky 9), a fresh install and an
  upgrade from the latest published release, then reinstall, remove and (deb)
  purge. Checks the `homer` user/group, owners and modes of the config and
  `/var/lib/heplify`, that files moved by older packages are gone, and what is
  kept on removal. Containers have no systemd, so the `systemctl` branches of
  the maintainer scripts are not run there.
- `scripts/test_package.sh e2e PACKAGE.deb` on the runner VM: starts the
  packaged service with a config that captures SIP on `lo`, and checks that it
  runs as `homer` with only `CAP_NET_RAW`, `CAP_NET_ADMIN` and
  `CAP_NET_BIND_SERVICE`, that a SIP packet arrives as HEP3 at a local UDP
  listener, and that the journal has no errors. It installs and removes the
  package on the host, so run it only on a throwaway machine.

The lifecycle test runs locally with Docker:

```bash
make package VERSION=99.0.0
./scripts/test_package.sh lifecycle debian:13 heplify-99.0.0-amd64.deb
./scripts/test_package.sh lifecycle rockylinux:9 heplify-99.0.0-amd64.rpm
```
