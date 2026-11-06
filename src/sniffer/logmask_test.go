package sniffer

import (
	"strings"
	"testing"
)

func TestMaskSIPCredentials(t *testing.T) {
	in := "REGISTER sip:x SIP/2.0\r\n" +
		"authorization: Digest username=\"bob\", response=\"secret\"\r\n" +
		"Proxy-Authorization: Basic Ym9iOnB3\r\n" +
		"Via: SIP/2.0/UDP h\r\n\r\nbody Authorization: keep"
	out := maskSIPCredentials([]byte(in))
	if strings.Contains(out, "secret") || strings.Contains(out, "Ym9iOnB3") {
		t.Fatalf("credentials not masked: %q", out)
	}
	for _, want := range []string{"authorization: Digest ***\r\n", "Proxy-Authorization: Basic ***\r\n", "Via: SIP/2.0/UDP h\r\n\r\nbody Authorization: keep"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	plain := "OPTIONS sip:x SIP/2.0\r\nVia: a\r\n\r\n"
	if got := maskSIPCredentials([]byte(plain)); got != plain {
		t.Fatalf("message without credentials changed: %q", got)
	}
}
