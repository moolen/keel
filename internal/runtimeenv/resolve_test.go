package runtimeenv

import (
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
)

func TestResolveMergesStaticHostAndCommand(t *testing.T) {
	t.Setenv("HOST_TOKEN", "secret")
	values, err := Resolve(config.EnvConfig{
		Static: map[string]string{
			"TERM": "xterm-256color",
		},
		FromHost: map[string]string{
			"TOKEN": "HOST_TOKEN",
		},
		FromCommand: map[string]config.EnvCommand{
			"BUILD_SHA": {Command: []string{"sh", "-lc", "printf 'abc123\\n'"}},
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := values["TERM"], "xterm-256color"; got != want {
		t.Fatalf("TERM = %q, want %q", got, want)
	}
	if got, want := values["TOKEN"], "secret"; got != want {
		t.Fatalf("TOKEN = %q, want %q", got, want)
	}
	if got, want := values["BUILD_SHA"], "abc123"; got != want {
		t.Fatalf("BUILD_SHA = %q, want %q", got, want)
	}
}

func TestResolveMissingHostEnvFails(t *testing.T) {
	_, err := Resolve(config.EnvConfig{
		FromHost: map[string]string{
			"TOKEN": "MISSING_TOKEN",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "MISSING_TOKEN") {
		t.Fatalf("Resolve() error = %v, want missing host env failure", err)
	}
}

func TestResolveCommandFailureFails(t *testing.T) {
	_, err := Resolve(config.EnvConfig{
		FromCommand: map[string]config.EnvCommand{
			"BAD": {Command: []string{"sh", "-lc", "echo nope >&2; exit 7"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("Resolve() error = %v, want command failure", err)
	}
}

func TestResolveRejectsMultilineOutput(t *testing.T) {
	_, err := Resolve(config.EnvConfig{
		FromCommand: map[string]config.EnvCommand{
			"BAD": {Command: []string{"sh", "-lc", "printf 'a\\nb\\n'"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Fatalf("Resolve() error = %v, want multiline rejection", err)
	}
}
