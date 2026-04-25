package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
)

func TestHostRunnerDryRunPrintsSummary(t *testing.T) {
	var stdout bytes.Buffer
	runner := HostRunner{}
	cfg := config.Default()
	cfg.Image = "debian:bookworm"
	cfg.DryRun = true

	err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh", "-lc", "echo hello"},
		Stdout:  &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "dry-run") || !strings.Contains(output, "debian:bookworm") {
		t.Fatalf("unexpected output: %q", output)
	}
}
