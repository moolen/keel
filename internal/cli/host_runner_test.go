package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/workspace"
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

func TestHostRunnerPreparesAssetsBeforeLaunch(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Workspace.Target = "/workspace"

	var prepareOpts workspace.PrepareOptions
	var machineAssets vm.RuntimeAssets

	runner := HostRunner{
		RuntimeDir: tempDir,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			prepareOpts = opts
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			machineAssets = assets
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if prepareOpts.SourceDir != sourceDir {
		t.Fatalf("prepare source dir = %q, want %q", prepareOpts.SourceDir, sourceDir)
	}
	if !strings.HasSuffix(machineAssets.RootfsPath, "/index.docker.io/library/ubuntu/24.04/rootfs.ext4") {
		t.Fatalf("rootfs path = %q", machineAssets.RootfsPath)
	}
	if machineAssets.WorkspacePath == "" {
		t.Fatal("workspace path should not be empty")
	}
}

func TestHostRunnerReturnsWorkspacePrepareError(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"

	runner := HostRunner{
		RuntimeDir: t.TempDir(),
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{}, errors.New("boom")
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run() error = %v, want propagated workspace failure", err)
	}
}

type stubMachineRunner struct{}

func (stubMachineRunner) Run(context.Context) error {
	return nil
}
