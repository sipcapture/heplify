#!/bin/sh

# Thanks @zecke42 for the idea to use musl!
# https://www.moiji-mobile.com/2017/10/15/static-binaries-for-go-with-docker/

# Make a static 64 bit binary:
# docker run --rm=true -itv $PWD:/mnt golang:alpine /mnt/build_static.sh

# Make a static 32 bit binary:
# docker run --rm=true -itv $PWD:/mnt i386/golang:alpine /mnt/build_static.sh

set -ex

apk update
apk add linux-headers musl-dev gcc libpcap-dev ca-certificates git

cd /mnt
rm -f heplify*
go build --ldflags '-linkmode external -extldflags "-static -s -w"' -v ./
./heplify -rf example/pcap/rtp_rtcp_sip_ipv4_udp.pcap -rs -e -hs ""
cp ./heplify /mnt/out/
