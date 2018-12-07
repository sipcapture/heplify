// +build gofuzz

package protos

// To run the fuzzer, first download go-fuzz:
// go get github.com/dvyukov/go-fuzz/...
//
// Then build the testing package:
// go-fuzz-build github.com/negbie/heplify/protos
//
// And run the fuzzer
//
// go-fuzz -bin=fuzz-protos.zip -workdir=workdir

func Fuzz(data []byte) int {
	ParseRTCP(data)
	return 0
}
