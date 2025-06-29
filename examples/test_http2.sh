#!/bin/bash

# Test script for heplify HTTP/2 functionality

echo "=== Testing heplify HTTP/2 functionality ==="

# Check if heplify is available
if ! command -v ./heplify &> /dev/null; then
    echo "Error: heplify not found in current directory"
    echo "Make sure you are running the script from the project root directory"
    exit 1
fi

# Create test HEP3 data
HEP3_DATA="\x48\x45\x50\x33\x00\x00\x00\x1A\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

echo "1. Starting heplify in HTTP/2 collector mode..."
echo "   ./heplify -hin http2://:8080 -e -l debug"

# Start heplify in background
./heplify -hin http2://:8080 -e -l debug &
HEPLIFY_PID=$!

# Wait a bit for startup
sleep 3

echo "2. Checking if server is running..."
if ! curl -s http://localhost:8080/hep > /dev/null 2>&1; then
    echo "   Error: HTTP/2 server is not responding"
    kill $HEPLIFY_PID 2>/dev/null
    exit 1
fi
echo "   ✓ HTTP/2 server is running"

echo "3. Sending test HEP3 packet..."
RESPONSE=$(echo -ne "$HEP3_DATA" | curl -s -X POST http://localhost:8080/hep \
  -H "Content-Type: application/octet-stream" \
  --http2 \
  --data-binary @-)

if [ "$RESPONSE" = "OK" ]; then
    echo "   ✓ HEP3 packet processed successfully"
else
    echo "   ✗ Error processing HEP3 packet: $RESPONSE"
fi

echo "4. Sending invalid data..."
RESPONSE=$(echo "invalid data" | curl -s -X POST http://localhost:8080/hep \
  -H "Content-Type: application/octet-stream" \
  --http2 \
  --data-binary @-)

if [[ "$RESPONSE" == *"Not HEP3 Data"* ]]; then
    echo "   ✓ Invalid data properly rejected"
else
    echo "   ✗ Invalid data was not rejected: $RESPONSE"
fi

echo "5. Stopping heplify..."
kill $HEPLIFY_PID 2>/dev/null
wait $HEPLIFY_PID 2>/dev/null

echo "=== Test completed ==="
echo ""
echo "For more detailed testing use:"
echo "  ./heplify -hin http2://:8080 -e -l debug"
echo "And in another terminal:"
echo "  curl -X POST http://localhost:8080/hep -H 'Content-Type: application/octet-stream' --http2 --data-binary @your_hep3_file" 