package internal

import "testing"

func TestEnsureResolverHostnameOverridesIPAddressHostname(t *testing.T) {
	var setValue string

	err := ensureResolverHostnameWith(
		func() (string, error) { return "172.22.55.26", nil },
		func(value []byte) error {
			setValue = string(value)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ensureResolverHostnameWith() error = %v", err)
	}
	if got, want := setValue, "keel"; got != want {
		t.Fatalf("set hostname = %q, want %q", got, want)
	}
}

func TestEnsureResolverHostnameKeepsSimpleHostname(t *testing.T) {
	var called bool

	err := ensureResolverHostnameWith(
		func() (string, error) { return "keel", nil },
		func([]byte) error {
			called = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ensureResolverHostnameWith() error = %v", err)
	}
	if called {
		t.Fatal("set hostname should not be called for a simple hostname")
	}
}
