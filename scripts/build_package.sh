#!/bin/bash

VERSION=$(cat $PWD/main.go | grep "const version" | grep -Po '\d.\d+.\d+')

PACKAGE=${PACKAGE:-"heplify"}
RELEASE=${VERSION:-"1.5.3"}
ARCH=${ARCH:-"amd64"}

# CHECK FOR DOCKER
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed. Exiting...' >&2
  exit 1
fi

echo "Packaging release $RELEASE ..."
# BUILD DEB PACKAGE
EXT="deb"
docker run --rm \
  -v $PWD:/tmp/pkg \
  -e VERSION="$RELEASE" \
  goreleaser/nfpm pkg --config /tmp/pkg/example/$PACKAGE.yaml --target "/tmp/pkg/$PACKAGE-$RELEASE-$ARCH.$EXT"

# BUILD RPM PACKAGE
EXT="rpm"
docker run --rm \
  -v $PWD:/tmp/pkg \
  -e VERSION="$RELEASE" \
  goreleaser/nfpm pkg --config /tmp/pkg/example/$PACKAGE.yaml --target "/tmp/pkg/$PACKAGE-$RELEASE-$ARCH.$EXT"
