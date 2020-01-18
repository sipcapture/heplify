#!/bin/bash
# CHECK FOR DOCKER
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed. Exiting...' >&2
  exit 1
fi

# BUILD GO BINARY
read -p "This will drop and rebuild the heplify binary from source. Continue (y/n)?" CONT
if [ "$CONT" = "y" ]; then
 docker run --rm \
  -v $PWD:/app \
  golang:1.13 \
  bash -c "apt update && apt install -y libpcap-dev && cd /app && make all"
else
  echo "Exiting..."
fi
