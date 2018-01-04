package sniffer

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"time"
)

func benchmark() {
	go func() {
		fmt.Println("Benchmark for the next 2 minutes")
		cpuFile, err := os.Create("cpu.pprof")
		if err != nil {
			fmt.Printf("Could not create CPU profile: %v", err)
		}
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			fmt.Printf("Could not start CPU profile: %v", err)
		}

		traceFile, err := os.Create("trace.out")
		if err != nil {
			fmt.Printf("Could not create trace file: %v", err)
		}
		if err := trace.Start(traceFile); err != nil {
			fmt.Printf("Could not start trace: %v", err)
		}

		time.Sleep(120 * time.Second)
		ramFile, err := os.Create("ram.pprof")
		if err != nil {
			fmt.Printf("Could not create RAM profile: %vs", err)
		}
		runtime.GC() // update gc statistics
		if err := pprof.WriteHeapProfile(ramFile); err != nil {
			fmt.Printf("Could not write RAM profile: %v", err)
		}
		ramFile.Close()

		pprof.StopCPUProfile()
		cpuFile.Close()

		trace.Stop()
		traceFile.Close()

		fmt.Println("Benchmark finished!")
		os.Exit(1)
	}()
}
