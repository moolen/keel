package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
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
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
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
		EnsureKernel: func(context.Context, string) (string, error) {
			return "/tmp/vmlinux", nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{}, errors.New("boom")
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run() error = %v, want propagated workspace failure", err)
	}
}

func TestHostRunnerAutoPullsMissingRootfs(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	var pulled bool
	var machineAssets vm.RuntimeAssets
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		PullImage: func(_ context.Context, cacheDir, ref string) (image.PullResult, error) {
			pulled = true
			if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
				return image.PullResult{}, err
			}
			if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
				return image.PullResult{}, err
			}
			return image.PullResult{Layout: image.CacheLayout{RootfsPath: rootfsPath}}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			machineAssets = assets
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !pulled {
		t.Fatal("expected missing rootfs to trigger image pull")
	}
	if machineAssets.RootfsPath != rootfsPath {
		t.Fatalf("machineAssets.RootfsPath = %q, want %q", machineAssets.RootfsPath, rootfsPath)
	}
}

func TestHostRunnerAppliesConfiguredFeaturesBeforeLaunch(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "docker:28-dind"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Features = []config.FeatureConfig{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver": "vfs",
		},
	}}

	var gotRootfsPath string
	var gotFeatures []config.FeatureConfig
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "docker", "28-dind", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		PrepareFeatures: func(rootfsPath string, configured []config.FeatureConfig) error {
			gotRootfsPath = rootfsPath
			gotFeatures = append([]config.FeatureConfig(nil), configured...)
			return nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if gotRootfsPath != rootfsPath {
		t.Fatalf("PrepareFeatures rootfs = %q, want %q", gotRootfsPath, rootfsPath)
	}
	if len(gotFeatures) != 1 || gotFeatures[0].Name != "docker" {
		t.Fatalf("PrepareFeatures features = %#v", gotFeatures)
	}
}

func TestHostRunnerWarnsWhenUsingDefaultKernelWithNetworkPolicy(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.DNS.Allowed = []string{"github.com"}

	var stderr bytes.Buffer
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return vm.DefaultKernelPath(), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(stderr.String(), "transparent tcp redirect is unavailable on the default kernel") {
		t.Fatalf("stderr = %q, want transparent redirect warning", stderr.String())
	}
}

func TestHostRunnerAllocatesUniqueRuntimeDirByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = t.TempDir()
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(cfg.ImageCacheDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var preparePaths []string
	runner := HostRunner{
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(t.TempDir(), "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			preparePaths = append(preparePaths, opts.ImagePath)
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	for range 2 {
		if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	}
	if len(preparePaths) != 2 {
		t.Fatalf("preparePaths = %d, want 2", len(preparePaths))
	}
	if preparePaths[0] == preparePaths[1] {
		t.Fatalf("workspace paths should differ, got %q", preparePaths[0])
	}
	for _, path := range preparePaths {
		if !strings.Contains(filepath.Base(filepath.Dir(path)), "keel-runtime-") {
			t.Fatalf("workspace path = %q, want generated keel-runtime directory", path)
		}
	}
}

func TestHostRunnerSyncsWorkspaceAfterCommandExit(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Workspace.SyncBack = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var syncOpts workspace.ImageSyncOptions
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			syncOpts = opts
			return workspace.SyncResult{Applied: true}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stdin:   strings.NewReader("y\n"),
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if syncOpts.HostDir != cfg.Workspace.Mount {
		t.Fatalf("sync host dir = %q, want %q", syncOpts.HostDir, cfg.Workspace.Mount)
	}
	if syncOpts.ImagePath == "" {
		t.Fatal("sync image path should not be empty")
	}
	if !syncOpts.Confirm {
		t.Fatal("sync confirm should follow workspace config")
	}
}

func TestHostRunnerReturnsSyncErrorAfterSuccessfulRun(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Workspace.SyncBack = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			return workspace.SyncResult{}, errors.New("sync failed")
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Fatalf("Run() error = %v, want sync failure", err)
	}
}

func TestHostRunnerStartServicesStartsDNSAndTCPProxies(t *testing.T) {
	runner := HostRunner{}
	assets := vm.RuntimeAssets{
		VSockPath: filepath.Join(t.TempDir(), "firecracker.vsock"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop, err := runner.startServices(ctx, config.Default(), assets)
	if err != nil {
		t.Fatalf("startServices() error = %v", err)
	}
	defer stop()

	for _, socketPath := range []string{assets.VSockPath + "_3053", assets.VSockPath + "_3128"} {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, statErr := os.Stat(socketPath); statErr == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("socket %q was not created in time", socketPath)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

type stubMachineRunner struct{}

func (stubMachineRunner) Run(context.Context) error {
	return nil
}
