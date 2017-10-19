#!/bin/sh

set -ex

apk update
apk add linux-headers musl-dev gcc go libpcap-dev ca-certificates  git

mkdir /go
export GOPATH=/go
mkdir -p /go/src/github.com/negbie
mkdir -p /mnt/out
cp -a /mnt /go/src/github.com/negbie/heplify
cd /go/src/github.com/negbie/heplify
rm -f heplify*
go get -v ./ ./
go build --ldflags '-linkmode external -extldflags "-static -s -w"' -v ./
cp ./heplify /mnt/out/
