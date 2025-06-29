package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run http2_client.go <server_address>")
		fmt.Println("Example: go run http2_client.go http2://localhost:8080")
		os.Exit(1)
	}

	serverAddr := os.Args[1]

	// Create HTTP/2 client
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing only
			},
		},
	}

	// Sample HEP3 packet (you can replace this with real HEP3 data)
	hep3Data := []byte{
		0x48, 0x45, 0x50, 0x33, // HEP3 magic
		0x00, 0x00, 0x00, 0x1A, // Length (26 bytes)
		0x00, 0x00, 0x00, 0x01, // Vendor ID
		0x00, 0x00, 0x00, 0x01, // Protocol Type (SIP)
		0x00, 0x00, 0x00, 0x00, // Source Port
		0x00, 0x00, 0x00, 0x00, // Destination Port
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, 0x00, 0x00, 0x00, // Timestamp microseconds
		0x00, 0x00, 0x00, 0x00, // Protocol Type
		0x00, 0x00, 0x00, 0x00, // Capture ID
		0x00, 0x00, 0x00, 0x00, // Keep Alive Timer
		0x00, 0x00, 0x00, 0x00, // Authenticate Key
		0x00, 0x00, 0x00, 0x00, // Payload
	}

	// Create request
	req, err := http.NewRequest("POST", serverAddr+"/hep", bytes.NewReader(hep3Data))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", string(body))
}
