package publish

import "os"

/*
Certificate, key and chain can be embedded before building the binary by
appending values to this file. (echo "var agentKey string = \`$( cat ../../heplify1.key )\`" >> publish/mtls.go)
But if not, then pem files can be specified via the command line flags
*/
var agentCert string
var agentKey string
var serverChain string

func loadFile(c string) (string, error) {
	f, err := os.ReadFile(c)
	if err != nil {
		return "", err
	}
	return string(f), nil
}
