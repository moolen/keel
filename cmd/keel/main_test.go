package main

import (
	"errors"
	"testing"
)

type stubExitCodeError struct {
	code int
}

func (e stubExitCodeError) Error() string {
	return "boom"
}

func (e stubExitCodeError) ExitCode() int {
	return e.code
}

func TestExitCodeForErrorUsesCustomExitCode(t *testing.T) {
	if got, want := exitCodeForError(stubExitCodeError{code: 42}), 42; got != want {
		t.Fatalf("exitCodeForError() = %d, want %d", got, want)
	}
}

func TestExitCodeForErrorDefaultsToOne(t *testing.T) {
	if got, want := exitCodeForError(errors.New("boom")), 1; got != want {
		t.Fatalf("exitCodeForError() = %d, want %d", got, want)
	}
}
