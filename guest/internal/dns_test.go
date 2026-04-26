package internal

import "testing"

func TestResolvConfContentsDisablesSearchSuffixes(t *testing.T) {
	got := resolvConfContents()
	want := "nameserver 127.0.0.1\nsearch .\noptions ndots:0\n"
	if got != want {
		t.Fatalf("resolvConfContents() = %q, want %q", got, want)
	}
}
