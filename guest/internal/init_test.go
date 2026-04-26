package internal

import (
	"errors"
	"os"
	"testing"
	"time"
)

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

func TestRunGuestTrustHookSkipsMissingHook(t *testing.T) {
	var called bool
	err := runGuestTrustHookWith(
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) error {
			called = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runGuestTrustHookWith() error = %v", err)
	}
	if called {
		t.Fatal("hook should not run when install-ca.sh is absent")
	}
}

func TestRunGuestTrustHookRunsPresentHook(t *testing.T) {
	var ran string
	err := runGuestTrustHookWith(
		func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		func(path string) error {
			ran = path
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runGuestTrustHookWith() error = %v", err)
	}
	if ran != "/etc/keel/install-ca.sh" {
		t.Fatalf("ran = %q, want trust hook path", ran)
	}
}

func TestRunGuestTrustHookReturnsRunError(t *testing.T) {
	want := errors.New("boom")
	err := runGuestTrustHookWith(
		func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		func(string) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("runGuestTrustHookWith() error = %v, want %v", err, want)
	}
}

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "install-ca.sh" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0o755 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
