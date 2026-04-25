package cli

import (
	"context"
	"testing"

	"github.com/moolen/keel/internal/config"
)

type stubRunner struct {
	request RunRequest
	called  bool
}

func (s *stubRunner) Run(_ context.Context, req RunRequest) error {
	s.called = true
	s.request = req
	return nil
}

func TestRootCommandRoutesCommandInvocation(t *testing.T) {
	runner := &stubRunner{}
	cmd := NewRootCommand(Dependencies{
		Runner: runner,
		LoadConfig: func(_ context.Context, opts config.LoadOptions) (config.Config, error) {
			cfg := config.Default()
			cfg.Workspace.Mount = opts.WorkingDir
			return cfg, nil
		},
	})
	cmd.SetArgs([]string{"--verbose", "--", "/bin/sh", "-lc", "echo test"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !runner.called {
		t.Fatal("runner was not called")
	}
	if !runner.request.Config.Verbose {
		t.Fatal("expected verbose config override")
	}
	if got, want := runner.request.Command[0], "/bin/sh"; got != want {
		t.Fatalf("command[0] = %q, want %q", got, want)
	}
}
