package apiserver

import "testing"

func TestSecretEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"secret", "secret", true},
		{"", "", true},
		{"secret", "secreT", false},
		{"secret", "secret1", false},
		{"secret1", "secret", false},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := secretEqual(c.a, c.b); got != c.want {
			t.Errorf("secretEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
