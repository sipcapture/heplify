#!/bin/sh

# Thanks @zecke42 for the idea to use musl!
# https://www.moiji-mobile.com/2017/10/15/static-binaries-for-go-with-docker/

# Make a static 64 bit binary:
# docker run --rm=true -itv $PWD:/mnt alpine:3.7 /mnt/build_static.sh

# Make a static 32 bit binary:
# docker run --rm=true -itv $PWD:/mnt i386/alpine:3.7 /mnt/build_static.sh

set -ex

apk update
apk add linux-headers musl-dev gcc go libpcap-dev ca-certificates git

mkdir /go
export GOPATH=/go
mkdir -p /go/src/github.com/negbie
mkdir -p /mnt/out
cp -a /mnt /go/src/github.com/negbie/heplify
cd /go/src/github.com/negbie/heplify
rm -f heplify*
go get -v ./ ./
go build --ldflags '-linkmode external -extldflags "-static -s -w"' -v ./
./heplify -rf example/rtp_rtcp_sip.pcap -rs -e
cp ./heplify /mnt/out/
