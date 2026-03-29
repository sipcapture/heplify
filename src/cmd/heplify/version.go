package main

// Version is the application version. Updated by the release build process via scripts/update_version.sh.
// Overridden at build time with -X main.Version=<ver> ldflags by GoReleaser and Makefile.
var Version = "2.0.0"

// BuildDate is the UTC build timestamp. Set via -X main.BuildDate=<date> ldflags at build time.
var BuildDate = "unknown"
