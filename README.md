# heplify-ng

**heplify-ng** is a next-generation HEP Agent and Collector for the SIPCAPTURE ecosystem, written in Go. It serves as a simplified, high-performance successor to legacy agents, designed to capture SIP, RTCP, and other VoIP-related traffic and send it to HOMER or other HEP-compliant monitoring systems.

## Features

- **Packet Sniffing**: Efficiently captures SIP and RTCP traffic from network interfaces.
- **HEP Collection**: Can act as a collector/aggregator for other HEP agents.
- **Lua Scripting**: Integrated Lua engine for custom packet processing, filtering, and logic.
- **Prometheus Metrics**: Built-in Prometheus exporter for monitoring agent performance and traffic stats.
- **Modern Configuration**: Uses simple JSON-based configuration (compatible with `heplify.go`).
- **High Performance**: Built on top of `gopacket` and optimized Go routines.

## Getting Started

### Prerequisites

- Linux OS (recommended)
- Go 1.21 or higher (for building from source)
- `libpcap-dev` (for packet capture support)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/sipcapture/heplify-ng.git
cd heplify-ng

# Build the binary
go build -o heplify-ng src/cmd/heplify-ng/main.go
```

### Running

By default, `heplify-ng` looks for a configuration file named `heplify.json` in the current directory, or you can specify a path.

```bash
# Run with default config lookup
./heplify-ng

# Run with specific config file
./heplify-ng -config /path/to/my/config.json
```

### Logging options

You can control log output with two short flags:

```bash
# Set log level (alias for -l)
./heplify-ng -x debug

# Log to stdout (instead of stderr)
./heplify-ng -S

# Use JSON log format
./heplify-ng -log-format=json

# Plain text log format (default)
./heplify-ng -log-format=text

# Combine both
./heplify-ng -x debug -S -config heplify-test.json

# Short + long examples
./heplify-ng -x debug -S -log-format=json -config heplify-test.json
./heplify-ng -l warn -log-format text -config heplify-test.json
```

### Example `-h` flags (logging)

```bash
Usage: ./heplify-ng [options]

Options:
  -l value
    	Log level [debug, info, warn, error]
  -x value
    	Log level [debug, info, warn, error]
  -log-format string
    	Log format [text|json] (default "text")
  -e
    	Log to stderr
  -S
    	Log to stdout
```

## Configuration

Configuration is handled via a JSON file. An example `heplify.json` is provided in the repository.

Key sections include:
- **SystemSettings**: Node naming and general options.
- **NetworkSettings**: Interface selection and promiscuous mode.
- **HepSettings**: Destination HEP server details (IP, Port, ID).
- **ScriptSettings**: Lua script path and activation.
- **PrometheusSettings**: Metrics listener configuration.

## Lua Scripting

`heplify-ng` supports Lua scripting to manipulate or filter packets before sending. See `example.lua` for a starting point.

## License

[AGPLv3](LICENSE)
