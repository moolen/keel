package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
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

func TestHostRunnerRefreshesCachedGuestAgentWhenDigestChanges(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for guest agent refresh tests")
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is required for guest agent refresh tests")
	}

	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	layout, err := image.ResolveCacheLayout(tempDir, cfg.Image)
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.RootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if _, err := image.CreateRootfsImage(image.CreateRootfsOptions{
		SourceDir: t.TempDir(),
		ImagePath: layout.RootfsPath,
		SizeMB:    128,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}
	if err := os.WriteFile(layout.AgentPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(agent digest) error = %v", err)
	}

	guestAssets := image.GuestAgentAssets{Binary: []byte("agent-new")}
	var machineAssets vm.RuntimeAssets
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return guestAssets, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			machineAssets = assets
			return stubMachineRunner{}
		},
		PrepareFeatures: func(string, []config.FeatureConfig) error { return nil },
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if machineAssets.RootfsPath != layout.RootfsPath {
		t.Fatalf("machineAssets.RootfsPath = %q, want %q", machineAssets.RootfsPath, layout.RootfsPath)
	}
	data, err := os.ReadFile(layout.AgentPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), guestAssets.Digest(); got != want {
		t.Fatalf("agent digest = %q, want %q", got, want)
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

func TestHostRunnerCleansUpEphemeralRuntimeDir(t *testing.T) {
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

	var runtimeDir string
	runner := HostRunner{
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(t.TempDir(), "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			runtimeDir = filepath.Dir(opts.ImagePath)
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runtimeDir == "" {
		t.Fatal("runtime dir should be captured")
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir %q should be removed, stat err=%v", runtimeDir, err)
	}
}

func TestHostRunnerRemovesArtifactsFromExplicitRuntimeDir(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

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
			if err := os.WriteFile(opts.ImagePath, []byte("workspace"), 0o644); err != nil {
				return workspace.PrepareResult{}, err
			}
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("runtime dir %q should remain, stat err=%v", tempDir, err)
	}
	for _, artifact := range []string{
		filepath.Join(tempDir, "workspace.ext4"),
		filepath.Join(tempDir, "firecracker.sock"),
		filepath.Join(tempDir, "firecracker.vsock"),
		filepath.Join(tempDir, "firecracker.vsock_3053"),
		filepath.Join(tempDir, "firecracker.vsock_3128"),
		filepath.Join(tempDir, "firecracker.log"),
	} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("artifact %q should be removed, stat err=%v", artifact, err)
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

func TestHostRunnerPrintsNetworkSummaryAfterShutdown(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	summary := network.NewSummary()
	summary.RecordDNS("api.github.com", network.Decision{Allowed: true})
	summary.RecordTCP("github.com", 443, network.Decision{Allowed: false})

	var stderr bytes.Buffer
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, string) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, summary, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stderr:  &stderr,
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	output := stderr.String()
	if !strings.Contains(output, "Network summary:") {
		t.Fatalf("stderr = %q, want network summary header", output)
	}
	if !strings.Contains(output, "dns  api.github.com:53 policy=allowed count=1") {
		t.Fatalf("stderr = %q, want dns summary entry", output)
	}
	if !strings.Contains(output, "tcp  github.com:443 policy=denied count=1") {
		t.Fatalf("stderr = %q, want tcp summary entry", output)
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
	instance := &stubHypervisorVM{
		listen: func(port uint32) (net.Listener, error) {
			return net.Listen("unix", filepath.Join(t.TempDir(), "vsock-"+strconv.Itoa(int(port))))
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop, summary, err := runner.startVMServices(ctx, config.Default(), instance)
	if err != nil {
		t.Fatalf("startServices() error = %v", err)
	}
	defer stop()
	if summary == nil {
		t.Fatal("startServices() summary should not be nil")
	}
	if got, want := instance.listenedPorts, []uint32{3053, 3128}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listened ports = %#v, want %#v", got, want)
	}
}

type stubMachineRunner struct{}

func (stubMachineRunner) Run(context.Context) error {
	return nil
}

type stubHypervisorVM struct {
	listen        func(uint32) (net.Listener, error)
	listenedPorts []uint32
}

func (*stubHypervisorVM) Start(context.Context) error { return nil }
func (*stubHypervisorVM) Stop(context.Context) error  { return nil }
func (*stubHypervisorVM) Wait(context.Context) error  { return nil }
func (*stubHypervisorVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go server.Close()
	return client, nil
}

func (v *stubHypervisorVM) VSockListen(port uint32) (net.Listener, error) {
	v.listenedPorts = append(v.listenedPorts, port)
	if v.listen != nil {
		return v.listen(port)
	}
	return nil, nil
}

var _ hypervisor.VM = (*stubHypervisorVM)(nil)
