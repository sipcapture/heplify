#!/bin/bash
# CHECK FOR DOCKER
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed. Exiting...' >&2
  exit 1
fi

# BUILD GO BINARY
docker run --rm \
  -v $PWD:/app \
  golang:alpine \
  sh -c "apk --update add linux-headers musl-dev gcc libpcap-dev ca-certificates git && cd /app && CGO_ENABLED=1 GOOS=linux go build -a --ldflags '-linkmode external -extldflags \"-static -s -w\"' -o heplify ."


