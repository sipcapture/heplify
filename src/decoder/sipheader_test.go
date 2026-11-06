package decoder

import "testing"

func TestSIPHeaderParsing(t *testing.T) {
	msg := []byte("INVITE sip:abc:5060 SIP/2.0\r\n" +
		"Contact: <sip:abc:5060>\r\n" +
		"CONTENT-LENGTH: 4\r\n" +
		"call-id: xyz@host\r\n" +
		"\r\n" +
		"Content-Length: 999\r\n")
	if n := sipContentLength(msg); n != 4 {
		t.Fatalf("Content-Length: got %d, want 4", n)
	}
	if v, ok := sipHeader(msg, "Call-ID", "i"); !ok || string(v) != "xyz@host" {
		t.Fatalf("Call-ID: got %q %v", v, ok)
	}
	// "c:" must not match inside the Contact value.
	if v, ok := sipHeader(msg, "Content-Type", "c"); ok {
		t.Fatalf("Content-Type should be absent, got %q", v)
	}
	// Body text must never be read as a header.
	body := []byte("SIP/2.0 200 OK\r\nVia: x\r\n\r\nl: 50\r\n")
	if n := sipContentLength(body); n != -1 {
		t.Fatalf("Content-Length read from body: %d", n)
	}
	compact := []byte("SIP/2.0 200 OK\nl: 7\n\n")
	if n := sipContentLength(compact); n != 7 {
		t.Fatalf("compact form with bare LF: got %d", n)
	}
}
