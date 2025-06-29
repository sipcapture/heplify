# HTTP/2 Support for HEP3 Collector

## Overview

Added support for HTTP/2 protocol to receive HEP3 packets in collector mode. This allows sending HEP3 data through HTTP/2 connections.

## Usage

### Run server in HTTP/2 collector mode

```bash
./heplify -collector http2://:8080
```

### Send HEP3 data via HTTP/2

#### Using curl:

```bash
# Prepare HEP3 data (example)
HEP3_DATA="\x48\x45\x50\x33\x00\x00\x00\x1A\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Send via HTTP/2
curl -X POST http://localhost:8080/hep \
  -H "Content-Type: application/octet-stream" \
  --http2 \
  --data-binary "$HEP3_DATA"
```

#### Using Go client:

```go
package main

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
    "golang.org/x/net/http2"
)

func main() {
    // HEP3 data
    hep3Data := []byte{
        0x48, 0x45, 0x50, 0x33, // HEP3 magic
        0x00, 0x00, 0x00, 0x1A, // Length
        0x00, 0x00, 0x00, 0x01, // Vendor ID
        0x00, 0x00, 0x00, 0x01, // Protocol Type (SIP)
        // ... other HEP3 fields
    }

    // Create HTTP/2 client
    client := &http.Client{
        Transport: &http2.Transport{},
    }

    // Send request
    req, _ := http.NewRequest("POST", "http://localhost:8080/hep", bytes.NewReader(hep3Data))
    req.Header.Set("Content-Type", "application/octet-stream")
    
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Response: %s\n", string(body))
}
```

## Configuration

### Filter only SIP packets

```bash
./heplify -collector http2://:8080 -collect-only-sip
```

### Filter by IP addresses

```bash
./heplify -collector http2://:8080 -discard-ip "192.168.1.1,10.0.0.1"
./heplify -collector http2://:8080 -discard-src-ip "192.168.1.1"
./heplify -collector http2://:8080 -discard-dst-ip "10.0.0.1"
```

## Response Structure

### Successful HEP3 packet processing
- **Status**: 200 OK
- **Body**: "OK"

### Errors
- **400 Bad Request**: Invalid data format or not HEP3 packet
- **500 Internal Server Error**: Internal server error

## Logging

HTTP/2 collector logs:
- New connection acceptance
- HEP3 packet reception
- Processing errors
- Packet type statistics

## Monitoring

Statistics available through Prometheus metrics:
- `connected_clients`: Number of active clients
- `client_last_metric_timestamp`: Time of last received packet

## Security

For production use, it is recommended to:
1. Use TLS certificates
2. Configure authentication
3. Restrict access by IP addresses
4. Monitor connection count 