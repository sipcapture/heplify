package decoder

import (
	"fmt"
	"net"
	"testing"
)

func sipSDPInvite(callID, sdpBody string) []byte {
	return []byte("INVITE sip:test@example.com SIP/2.0\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		sdpBody)
}

func sdpAudio(rtcpAttr string) string {
	body := "v=0\r\n" +
		"o=- 0 0 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 12345 RTP/AVP 0\r\n"
	if rtcpAttr != "" {
		body += rtcpAttr + "\r\n"
	}
	return body
}

func TestExtractCID_MalformedRtcpLineDoesNotPanic(t *testing.T) {
	cases := []struct {
		name string
		attr string
	}{
		{name: "IPv4 type without address", attr: "a=rtcp:12345 IN IP4"},
		{name: "IPv6 type without address", attr: "a=rtcp:12345 IN IP6"},
		{name: "IN IP prefix only", attr: "a=rtcp:12345 IN IP"},
		{name: "IPv4 type with trailing space", attr: "a=rtcp:12345 IN IP4 "},
	}

	src := net.ParseIP("127.0.0.1")
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			callID := fmt.Sprintf("malformed-%d", i)
			payload := sipSDPInvite(callID, sdpAudio(tc.attr))
			ExtractCID(src, 5060, src, 5060, payload)

			// Port from a=rtcp is kept; missing address falls back to session c= IP.
			got, ok := cidCache.Get("127.0.0.1 12345")
			if !ok {
				t.Fatal("expected cidCache entry using session IP and a=rtcp port")
			}
			if string(got) != callID {
				t.Fatalf("callID: got %q want %q", got, callID)
			}
		})
	}
}

func TestExtractCID_RtcpWithAddressCachesIPAndPort(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	callID := "valid-rtcp-ip"
	payload := sipSDPInvite(callID, sdpAudio("a=rtcp:53020 IN IP4 126.16.64.4"))

	ExtractCID(src, 5060, src, 5060, payload)

	got, ok := cidCache.Get("126.16.64.4 53020")
	if !ok {
		t.Fatal("expected cidCache entry for SDP RTCP IP:port")
	}
	if string(got) != callID {
		t.Fatalf("callID: got %q want %q", got, callID)
	}
}

func TestExtractCID_RtcpPortOnlyKeepsSessionIP(t *testing.T) {
	src := net.ParseIP("10.0.0.2")
	callID := "rtcp-port-only"
	payload := sipSDPInvite(callID, sdpAudio("a=rtcp:53020"))

	ExtractCID(src, 5060, src, 5060, payload)

	got, ok := cidCache.Get("127.0.0.1 53020")
	if !ok {
		t.Fatal("expected cidCache entry using session c= IP and a=rtcp port")
	}
	if string(got) != callID {
		t.Fatalf("callID: got %q want %q", got, callID)
	}
}
