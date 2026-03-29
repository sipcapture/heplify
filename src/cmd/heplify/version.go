package main

import (
	"fmt"
	"runtime"
)

// Version is set at build time via -X main.Version=<ver> ldflags.
var Version = "2.0.0"

// BuildDate is set at build time via -X main.BuildDate=<date> ldflags.
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
