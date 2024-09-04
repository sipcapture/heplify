package publish

import "os"

/*
Certificate, key and chain can be embedded before building the binary by
appending values to this file. (echo "var agentKey string = \`$( cat ../../heplify1.key )\`" >> publish/mtls.go)
But if not, then pem files can be specified via the command line flags. The function below is used by publish/hep.go to load the files
*/

func loadFile(c string) (string, error) {
	f, err := os.ReadFile(c)
	if err != nil {
		return "", err
	}
	return string(f), nil
}

/*
Embed cert, key or chain by specifying base64 value below. Note use of back ticks!!
Example:

var agentCert string = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOoqfvFoQXUULe
...
xkKI+Y6MRPBb2qXcYfeS/0FI
-----END PRIVATE KEY-----`
*/

var agentCert string
var serverChain string
var agentKey string
