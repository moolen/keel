package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/vsock"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func stubGuestAssets() (image.GuestAgentAssets, error) {
	return image.GuestAgentAssets{}, nil
}

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

func TestForwardedPTYStdinSkipsNonTerminalWhenSyncConfirmEnabled(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	cfg := config.Default()
	cfg.Workspace.SyncConfirm = true
	if got := forwardedPTYStdin(RunRequest{Config: cfg, Stdin: stdin}); got != nil {
		t.Fatalf("forwardedPTYStdin() = %v, want nil", got)
	}
}

func TestForwardedPTYStdinAllowsNonTerminalWithoutSyncConfirm(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	cfg := config.Default()
	cfg.Workspace.SyncConfirm = false
	if got := forwardedPTYStdin(RunRequest{Config: cfg, Stdin: stdin}); got != stdin {
		t.Fatalf("forwardedPTYStdin() = %v, want %v", got, stdin)
	}
}

func TestRunPreparedVMLeavesPipedInputForSyncConfirmation(t *testing.T) {
	tempDir := t.TempDir()
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()
	if _, err := stdin.WriteString("y\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}

	cfg := config.Default()
	cfg.Network.Mode = "none"
	cfg.Workspace.SyncBack = true
	cfg.Workspace.SyncConfirm = true

	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)
	vmInstance := &capturePTYInputVM{}
	machine := vm.NewMachine(cfg, assets)
	machine.NewVM = func(hypervisor.Config) (hypervisor.VM, error) {
		return vmInstance, nil
	}

	var stdout bytes.Buffer
	var syncInput string
	runner := HostRunner{
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			data, err := io.ReadAll(opts.In)
			if err != nil {
				return workspace.SyncResult{}, err
			}
			syncInput = string(data)
			return workspace.SyncResult{Applied: true}, nil
		},
	}

	req := RunRequest{
		Config: cfg,
		Stdin:  stdin,
		Stdout: &stdout,
	}
	if err := runner.runPreparedVM(context.Background(), req, machine, nopProgressReporter{}); err != nil {
		t.Fatalf("runPreparedVM() error = %v", err)
	}
	if err := runner.syncWorkspace(req, assets); err != nil {
		t.Fatalf("syncWorkspace() error = %v", err)
	}
	if got := vmInstance.Input(); got != "" {
		t.Fatalf("PTY input = %q, want empty", got)
	}
	if got, want := syncInput, "y\n"; got != want {
		t.Fatalf("sync input = %q, want %q", got, want)
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
	if machineAssets.RootfsPath == rootfsPath {
		t.Fatalf("rootfs path = %q, want runtime copy instead of cache image", machineAssets.RootfsPath)
	}
	if got, want := filepath.Base(machineAssets.RootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("runtime rootfs base = %q, want %q", got, want)
	}
	if !strings.HasPrefix(machineAssets.RootfsPath, tempDir) {
		t.Fatalf("runtime rootfs path = %q, want path under runtime dir %q", machineAssets.RootfsPath, tempDir)
	}
	if machineAssets.WorkspacePath == "" {
		t.Fatal("workspace path should not be empty")
	}
}

func TestHostRunnerExpandsRuntimeRootfsWhenRootDiskConfigured(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for rootfs resize tests")
	}
	if _, err := exec.LookPath("resize2fs"); err != nil {
		t.Skip("resize2fs is required for rootfs resize tests")
	}

	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Resources.RootDiskMB = 2304

	rootfsSource := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfsSource, "issue"), []byte("keel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if _, err := image.CreateRootfsImage(image.CreateRootfsOptions{
		SourceDir: rootfsSource,
		ImagePath: rootfsPath,
		SizeMB:    2048,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}

	var gotRootfsSize int64
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			info, err := os.Stat(assets.RootfsPath)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", assets.RootfsPath, err)
			}
			gotRootfsSize = info.Size()
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got, want := gotRootfsSize, int64(cfg.Resources.RootDiskMB)*1024*1024; got < want {
		t.Fatalf("runtime rootfs size = %d, want at least %d", got, want)
	}
}

func TestHostRunnerFailsFastWhenRuntimeSpaceIsInsufficient(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Resources.RootDiskMB = 4096
	cfg.Resources.DiskMB = 1024

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	workspacePrepared := false
	runner := HostRunner{
		RuntimeDir: tempDir,
		RuntimeFreeBytes: func(string) (uint64, error) {
			return 512 * 1024 * 1024, nil
		},
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			workspacePrepared = true
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	_, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err == nil {
		t.Fatal("prepareAssets() error = nil, want insufficient runtime space error")
	}
	if !strings.Contains(err.Error(), "insufficient free space for runtime data") {
		t.Fatalf("prepareAssets() error = %v, want insufficient free space error", err)
	}
	if workspacePrepared {
		t.Fatal("workspace preparer should not run when runtime storage is insufficient")
	}
}

func TestCopyRuntimeRootfsPreservesSparseFiles(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.ext4")
	runtimePath := filepath.Join(tempDir, "runtime.ext4")

	src, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	const logicalSize = int64(1 << 30)
	if err := src.Truncate(logicalSize); err != nil {
		t.Fatalf("Truncate() error = %v", err)
	}
	if _, err := src.WriteAt([]byte("keel"), 0); err != nil {
		t.Fatalf("WriteAt(start) error = %v", err)
	}
	if _, err := src.WriteAt([]byte("agent"), logicalSize-int64(len("agent"))); err != nil {
		t.Fatalf("WriteAt(end) error = %v", err)
	}
	if err := src.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := copyRuntimeRootfs(sourcePath, runtimePath); err != nil {
		t.Fatalf("copyRuntimeRootfs() error = %v", err)
	}

	srcInfo, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatalf("Stat(source) error = %v", err)
	}
	dstInfo, err := os.Stat(runtimePath)
	if err != nil {
		t.Fatalf("Stat(runtime) error = %v", err)
	}
	if got, want := dstInfo.Size(), srcInfo.Size(); got != want {
		t.Fatalf("runtime size = %d, want %d", got, want)
	}

	srcBlocks := statBlocks(t, srcInfo)
	dstBlocks := statBlocks(t, dstInfo)
	if srcBlocks == 0 || dstBlocks == 0 {
		t.Skip("filesystem does not report sparse allocation blocks")
	}
	if dstBlocks > srcBlocks*4 {
		t.Fatalf("runtime blocks = %d, want sparse copy close to source blocks %d", dstBlocks, srcBlocks)
	}
}

func statBlocks(t *testing.T, info os.FileInfo) int64 {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("stat blocks unavailable")
	}
	return stat.Blocks
}

func TestHostRunnerDefaultKernelResolutionPrefersKernelPath(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	kernelPath := filepath.Join(tempDir, "custom-vmlinux")
	if err := os.WriteFile(kernelPath, []byte("kernel"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg.Kernel.Path = kernelPath
	cfg.Kernel.Source = "https://example.com/ignored-vmlinux"

	writeCachedRootfsForHostRunnerTest(t, tempDir, cfg.Image)

	runner := HostRunner{
		RuntimeDir:  tempDir,
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	assets, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err != nil {
		t.Fatalf("prepareAssets() error = %v", err)
	}
	if got, want := assets.KernelPath, kernelPath; got != want {
		t.Fatalf("assets.KernelPath = %q, want %q", got, want)
	}
}

func TestHostRunnerPassesDefaultKernelSourceToResolution(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	writeCachedRootfsForHostRunnerTest(t, tempDir, cfg.Image)

	var gotKernelCfg config.KernelConfig
	resolvedKernelPath := filepath.Join(tempDir, "resolved-vmlinux")
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(_ context.Context, kernelCfg config.KernelConfig) (string, error) {
			gotKernelCfg = kernelCfg
			return resolvedKernelPath, nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	assets, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err != nil {
		t.Fatalf("prepareAssets() error = %v", err)
	}
	if got, want := gotKernelCfg.Source, "release://latest"; got != want {
		t.Fatalf("kernel source = %q, want %q", got, want)
	}
	if gotKernelCfg.Path != "" {
		t.Fatalf("kernel path = %q, want empty", gotKernelCfg.Path)
	}
	if got, want := assets.KernelPath, resolvedKernelPath; got != want {
		t.Fatalf("assets.KernelPath = %q, want %q", got, want)
	}
}

func TestHostRunnerPassesKernelSourceToResolution(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Kernel.Source = "https://example.com/vmlinux"

	writeCachedRootfsForHostRunnerTest(t, tempDir, cfg.Image)

	var gotKernelCfg config.KernelConfig
	resolvedKernelPath := filepath.Join(tempDir, "resolved-vmlinux")
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(_ context.Context, kernelCfg config.KernelConfig) (string, error) {
			gotKernelCfg = kernelCfg
			return resolvedKernelPath, nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	assets, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err != nil {
		t.Fatalf("prepareAssets() error = %v", err)
	}
	if got, want := gotKernelCfg.Source, cfg.Kernel.Source; got != want {
		t.Fatalf("kernel source = %q, want %q", got, want)
	}
	if gotKernelCfg.Path != "" {
		t.Fatalf("kernel path = %q, want empty", gotKernelCfg.Path)
	}
	if got, want := assets.KernelPath, resolvedKernelPath; got != want {
		t.Fatalf("assets.KernelPath = %q, want %q", got, want)
	}
}

func TestHostRunnerRefreshesLegacyCachedRootfsWhenOCITarballExists(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Workspace.Target = "/workspace"

	layout, err := image.ResolveCacheLayout(tempDir, cfg.Image)
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(layout.Directory, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	for _, item := range []struct {
		path string
		data string
	}{
		{path: layout.RootfsPath, data: "stale-rootfs"},
		{path: layout.OCIPath, data: "cached-oci"},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", item.path, err)
		}
	}

	pullCalls := 0
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		PullImage: func(_ context.Context, cacheDir, ref string) (image.PullResult, error) {
			pullCalls++
			if cacheDir != tempDir {
				t.Fatalf("cacheDir = %q, want %q", cacheDir, tempDir)
			}
			if ref != cfg.Image {
				t.Fatalf("ref = %q, want %q", ref, cfg.Image)
			}
			if err := os.WriteFile(layout.RootfsPath, []byte("refreshed-rootfs"), 0o644); err != nil {
				return image.PullResult{}, err
			}
			if err := image.WriteCacheVersion(layout.VersionPath); err != nil {
				return image.PullResult{}, err
			}
			return image.PullResult{Layout: layout}, nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if pullCalls != 1 {
		t.Fatalf("pullCalls = %d, want 1", pullCalls)
	}
}

func TestHostRunnerReturnsWorkspacePrepareError(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		PullImage: func(_ context.Context, cacheDir, ref string) (image.PullResult, error) {
			rootfsPath := filepath.Join(cacheDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
			if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
				return image.PullResult{}, err
			}
			if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
				return image.PullResult{}, err
			}
			return image.PullResult{Layout: image.CacheLayout{RootfsPath: rootfsPath}}, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{}, errors.New("boom")
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run() error = %v, want propagated workspace failure", err)
	}
}

func TestHostRunnerRuntimeConfigMaterializesEnv(t *testing.T) {
	cfg := config.Default()
	cfg.Env.Static["CI"] = "1"
	cfg.Env.FromHost = map[string]string{
		"TOKEN": "HOST_TOKEN",
	}
	t.Setenv("HOST_TOKEN", "secret")

	runner := HostRunner{
		ResolveEnv: func(env config.EnvConfig) (map[string]string, error) {
			return map[string]string{
				"CI":    env.Static["CI"],
				"TOKEN": "secret",
			}, nil
		},
	}
	runtimeCfg, err := runner.runtimeConfig(cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if got, want := runtimeCfg.RuntimeEnv["TOKEN"], "secret"; got != want {
		t.Fatalf("runtime env TOKEN = %q, want %q", got, want)
	}
}

func TestHostRunnerPreparesVolumeAndMetadataAssets(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	volumeDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Workspace.Target = "/workspace"
	cfg.RuntimeEnv = map[string]string{"TERM": "xterm-256color"}
	cfg.Volumes = []config.VolumeConfig{{
		Source:    volumeDir,
		Target:    "/cache",
		Ownership: "host",
	}}

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var manifest pkgboot.Manifest
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		VolumePreparer: func(opts volume.PrepareOptions) (volume.PrepareResult, error) {
			return volume.PrepareResult{ImagePath: opts.ImagePath, Kind: "dir"}, nil
		},
		WriteBootManifest: func(path string, item pkgboot.Manifest) error {
			manifest = item
			return os.WriteFile(path, []byte("meta"), 0o644)
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		PrepareFeatures: func(string, []config.FeatureConfig) error { return nil },
	}

	assets, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err != nil {
		t.Fatalf("prepareAssets() error = %v", err)
	}
	if got, want := len(assets.Volumes), 1; got != want {
		t.Fatalf("len(assets.Volumes) = %d, want %d", got, want)
	}
	if got, want := assets.Volumes[0].DevicePath, "/dev/vdd"; got != want {
		t.Fatalf("assets.Volumes[0].DevicePath = %q, want %q", got, want)
	}
	if got, want := manifest.Volumes[0].Target, "/cache"; got != want {
		t.Fatalf("manifest volume target = %q, want %q", got, want)
	}
}

func TestPrepareAssetsReturnsGuestAssetLoadError(t *testing.T) {
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, errors.New("guest agent missing")
		},
	}

	_, err := runner.prepareAssets(context.Background(), cfg, nopProgressReporter{})
	if err == nil || !strings.Contains(err.Error(), "guest agent missing") {
		t.Fatalf("prepareAssets() error = %v, want guest asset load error", err)
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
	if machineAssets.RootfsPath == rootfsPath {
		t.Fatalf("machineAssets.RootfsPath = %q, want runtime copy distinct from pulled cache rootfs", machineAssets.RootfsPath)
	}
	if got, want := filepath.Base(machineAssets.RootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("runtime rootfs base = %q, want %q", got, want)
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
	var runtimeAgent string
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
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
			runtimeAgent = debugfsReadCLI(t, assets.RootfsPath, "/usr/local/bin/keel-agent")
			return stubMachineRunner{}
		},
		PrepareFeatures: func(string, []config.FeatureConfig) error { return nil },
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if machineAssets.RootfsPath == layout.RootfsPath {
		t.Fatalf("machineAssets.RootfsPath = %q, want runtime copy distinct from cache rootfs", machineAssets.RootfsPath)
	}
	data, err := os.ReadFile(layout.AgentPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), guestAssets.Digest(); got != want {
		t.Fatalf("agent digest = %q, want %q", got, want)
	}
	if got := runtimeAgent; got != "agent-new" {
		t.Fatalf("runtime rootfs keel-agent = %q, want refreshed guest agent", got)
	}
}

func TestHostRunnerInjectsMITMGuestTrustAssets(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for guest trust tests")
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is required for guest trust tests")
	}

	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.MITM.CA.InstallSystem = true

	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tempDir)
	_ = oldHome

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

	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			if got := debugfsReadCLI(t, assets.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); got == "" {
				t.Fatal("expected injected mitm trust certificate")
			}
			if got := debugfsReadCLI(t, assets.RootfsPath, "/etc/keel/install-ca.sh"); !strings.Contains(got, "update-ca-certificates") {
				t.Fatalf("install-ca.sh content = %q", got)
			}
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got, ok := debugfsReadCLIIfPresent(t, layout.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); ok && got != "" {
		t.Fatal("cache rootfs should remain untouched by runtime guest trust injection")
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
	if gotRootfsPath == rootfsPath {
		t.Fatalf("PrepareFeatures rootfs = %q, want runtime copy distinct from cache rootfs", gotRootfsPath)
	}
	if got, want := filepath.Base(gotRootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("PrepareFeatures runtime rootfs base = %q, want %q", got, want)
	}
	if len(gotFeatures) != 1 || gotFeatures[0].Name != "docker" {
		t.Fatalf("PrepareFeatures features = %#v", gotFeatures)
	}
}

func TestHostRunnerRuntimeConfigInjectsDockerMITMCAPEM(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := config.Default()
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.MITM.CA.InstallDocker = true
	cfg.Features = []config.FeatureConfig{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver": "vfs",
		},
	}}

	runner := HostRunner{}
	runtimeCfg, err := runner.runtimeConfig(cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if len(runtimeCfg.Features) != 1 {
		t.Fatalf("len(runtimeCfg.Features) = %d, want 1", len(runtimeCfg.Features))
	}
	value, ok := runtimeCfg.Features[0].Config["mitm_ca_pem"].(string)
	if !ok || !strings.Contains(value, "BEGIN CERTIFICATE") {
		t.Fatalf("mitm_ca_pem = %#v, want CA PEM string", runtimeCfg.Features[0].Config["mitm_ca_pem"])
	}
}

func TestBuildNetworkServicesEnablesMITMProxy(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := config.Default()
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.HTTP.Default = "deny"
	cfg.Network.HTTP.Rules = []config.HTTPRuleConfig{{
		Action:  "allow",
		Host:    "api.github.com",
		Methods: []string{"GET"},
		Paths:   []string{"/repos/*"},
	}}

	_, tcpProxy, summary, err := buildNetworkServices(cfg)
	if err != nil {
		t.Fatalf("buildNetworkServices() error = %v", err)
	}
	if summary == nil {
		t.Fatal("expected summary")
	}
	if tcpProxy.MITM == nil {
		t.Fatal("expected MITM proxy to be enabled")
	}
	if tcpProxy.MITM.Policy == nil {
		t.Fatal("expected HTTP policy on MITM proxy")
	}
	decision := tcpProxy.MITM.Policy.Evaluate(network.HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/repos/123",
	})
	if !decision.Allowed {
		t.Fatalf("http policy decision = %#v, want allowed", decision)
	}
}

func TestBuildNetworkServicesEnablesAuditMode(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := config.Default()
	cfg.Network.Audit = true
	cfg.Network.DNS.Denied = []string{"gist.github.com"}
	cfg.Network.HTTP.Default = "deny"
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"

	dnsProxy, tcpProxy, _, err := buildNetworkServices(cfg)
	if err != nil {
		t.Fatalf("buildNetworkServices() error = %v", err)
	}

	dnsDecision := dnsProxy.Policy.EvaluateDNS("gist.github.com")
	if !dnsDecision.Allowed || !dnsDecision.WouldDeny {
		t.Fatalf("dns audit decision = %+v, want allowed+would_deny", dnsDecision)
	}
	if tcpProxy.MITM == nil || tcpProxy.MITM.Policy == nil {
		t.Fatal("expected MITM proxy with HTTP policy")
	}
	httpDecision := tcpProxy.MITM.Policy.Evaluate(network.HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/private",
	})
	if !httpDecision.Allowed || !httpDecision.WouldDeny {
		t.Fatalf("http audit decision = %+v, want allowed+would_deny", httpDecision)
	}
}

func TestHostRunnerWarnsWhenNetworkAuditModeIsEnabled(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.Audit = true

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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
	if !strings.Contains(stderr.String(), "network audit mode enabled") {
		t.Fatalf("stderr = %q, want audit warning", stderr.String())
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
		RuntimeFreeBytes: func(string) (uint64, error) {
			return ^uint64(0), nil
		},
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(t.TempDir(), "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
		if !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "vm-") {
			t.Fatalf("workspace path = %q, want generated vm directory", path)
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
		RuntimeFreeBytes: func(string) (uint64, error) {
			return ^uint64(0), nil
		},
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(t.TempDir(), "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
		filepath.Join(tempDir, "rootfs.ext4"),
		filepath.Join(tempDir, "workspace.ext4"),
		filepath.Join(tempDir, "firecracker.sock"),
		filepath.Join(tempDir, "firecracker.vsock"),
		filepath.Join(tempDir, "firecracker.vsock_3053"),
		filepath.Join(tempDir, "firecracker.vsock_3128"),
		filepath.Join(tempDir, "logs", "firecracker.log"),
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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

func TestHostRunnerReportsStartupPhasesInOrderAndStopsBeforeMachineRun(t *testing.T) {
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

	var events []string
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, network.NewSummary(), nil
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				events = append(events, "machine-run")
				return nil
			})
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantPhases := []string{
		"resolving config",
		"resolving runtime env",
		"ensuring kernel",
		"pulling oci image",
		"preparing guest assets",
		"preparing workspace image",
		"preparing extra volumes",
		"writing boot metadata image",
		"starting vm services",
		"booting vm and attaching terminal",
		"progress-stop",
		"machine-run",
	}
	if !reflect.DeepEqual(events, wantPhases) {
		t.Fatalf("events = %#v, want %#v", events, wantPhases)
	}
}

func TestHostRunnerStopsProgressBeforeAuditWarningAndMachineRun(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.Audit = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var (
		events []string
		stderr bytes.Buffer
	)
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, network.NewSummary(), nil
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				events = append(events, "machine-run")
				if got := events[len(events)-2]; got != "progress-stop" {
					return fmt.Errorf("event before machine-run = %q, want progress-stop", got)
				}
				if !strings.Contains(stderr.String(), "warning: network audit mode enabled") {
					return fmt.Errorf("stderr = %q, want audit warning", stderr.String())
				}
				return nil
			})
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
}

func TestHostRunnerStopsProgressBeforeReturningStartupError(t *testing.T) {
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

	var events []string
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
		WorkspacePreparer: func(workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{}, errors.New("workspace exploded")
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}, Stderr: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "workspace exploded") {
		t.Fatalf("Run() error = %v, want workspace error", err)
	}
	wantEvents := []string{
		"resolving config",
		"resolving runtime env",
		"ensuring kernel",
		"pulling oci image",
		"preparing guest assets",
		"preparing workspace image",
		"progress-stop",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
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
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: stubGuestAssets,
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

type machineRunnerFunc func(context.Context) error

func (f machineRunnerFunc) Run(ctx context.Context) error {
	return f(ctx)
}

type recordingProgressReporter struct {
	onStep    func(startupStep)
	onStop    func()
	lastTitle string
}

func (r *recordingProgressReporter) Step(step startupStep) {
	if step.Title == r.lastTitle {
		return
	}
	r.lastTitle = step.Title
	if r.onStep != nil {
		r.onStep(step)
	}
}

func (r *recordingProgressReporter) Stop() {
	if r.onStop != nil {
		r.onStop()
	}
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

type capturePTYInputVM struct {
	mu    sync.Mutex
	input bytes.Buffer
}

func (*capturePTYInputVM) Start(context.Context) error { return nil }
func (*capturePTYInputVM) Stop(context.Context) error  { return nil }
func (*capturePTYInputVM) Wait(context.Context) error  { return nil }

func (*capturePTYInputVM) VSockListen(port uint32) (net.Listener, error) {
	return net.Listen("unix", filepath.Join(os.TempDir(), "keel-vsock-"+strconv.Itoa(int(port))+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)))
}

func (v *capturePTYInputVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			frame, err := vsock.ReadFrame(server)
			if err != nil {
				break
			}
			if frame.Type == vsock.MessageData {
				v.mu.Lock()
				_, _ = v.input.Write(frame.Data)
				v.mu.Unlock()
			}
		}
		_ = vsock.WriteExitFrame(server, 0)
	}()
	return client, nil
}

func (v *capturePTYInputVM) Input() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.input.String()
}

func runtimeAssetsForHostRunnerVMTest(t *testing.T, dir string) vm.RuntimeAssets {
	t.Helper()
	assets := vm.RuntimeAssets{
		KernelPath:    filepath.Join(dir, "vmlinux"),
		RootfsPath:    filepath.Join(dir, "rootfs.ext4"),
		WorkspacePath: filepath.Join(dir, "workspace.ext4"),
		MetadataPath:  filepath.Join(dir, "bootmeta.ext4"),
		SocketPath:    filepath.Join(dir, "firecracker.sock"),
		VSockPath:     filepath.Join(dir, "firecracker.vsock"),
		LogPath:       filepath.Join(dir, "firecracker.log"),
		RuntimeDir:    dir,
		CID:           52,
	}
	for _, path := range []string{assets.KernelPath, assets.RootfsPath, assets.WorkspacePath, assets.MetadataPath} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}
	return assets
}

func writeCachedRootfsForHostRunnerTest(t *testing.T, cacheDir, imageRef string) string {
	t.Helper()
	layout, err := image.ResolveCacheLayout(cacheDir, imageRef)
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.RootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(layout.RootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return layout.RootfsPath
}

func debugfsReadCLI(t *testing.T, imagePath, target string) string {
	t.Helper()
	cmd := exec.Command("debugfs", "-R", "cat "+target, imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("debugfs read %s error = %v: %s", target, err, output)
	}
	text := string(output)
	if lines := strings.SplitN(text, "\n", 2); len(lines) == 2 && strings.HasPrefix(lines[0], "debugfs ") {
		return lines[1]
	}
	return text
}

func debugfsReadCLIIfPresent(t *testing.T, imagePath, target string) (string, bool) {
	t.Helper()
	cmd := exec.Command("debugfs", "-R", "cat "+target, imagePath)
	output, err := cmd.CombinedOutput()
	if strings.Contains(string(output), "File not found") {
		return "", false
	}
	if err != nil {
		t.Fatalf("debugfs read %s error = %v: %s", target, err, output)
	}
	text := string(output)
	if lines := strings.SplitN(text, "\n", 2); len(lines) == 2 && strings.HasPrefix(lines[0], "debugfs ") {
		return lines[1], true
	}
	return text, true
}
