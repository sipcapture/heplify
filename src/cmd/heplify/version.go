package main

import (
	"fmt"
	"runtime"
)

// Version is the application version. Updated by the release build process via scripts/update_version.sh.
// Overridden at build time with -X main.Version=<ver> ldflags by GoReleaser and Makefile.
var Version = "2.0.10"

// BuildDate is the UTC build timestamp. Set via -X main.BuildDate=<date> ldflags at build time.
var BuildDate = "unknown"

// GitCommit is set at build time via -X main.GitCommit=<sha> ldflags.
var GitCommit = "unknown"

// printVersion prints a detailed version dump similar to other SIPCAPTURE agents.
func printVersion() {
	fmt.Printf("heplify v%s\n", Version)
	fmt.Printf("\n")
	fmt.Printf("  Build date : %s\n", BuildDate)
	fmt.Printf("  Git commit : %s\n", GitCommit)
	fmt.Printf("  Go version : %s\n", runtime.Version())
	fmt.Printf("  OS/Arch    : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Go MAXPROCS: %d / NumCPU: %d\n", runtime.GOMAXPROCS(0), runtime.NumCPU())
}
