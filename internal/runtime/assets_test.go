package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func TestAssetPreparerCopiesCachedRootfsIntoRuntimeAssets(t *testing.T) {
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
	cachedData := []byte("cached rootfs")
	if err := os.WriteFile(layout.RootfsPath, cachedData, 0o644); err != nil {
		t.Fatalf("WriteFile(rootfs) error = %v", err)
	}

	var prepareOpts workspace.PrepareOptions
	preparer := AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			prepareOpts = opts
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	assets, err := preparer.Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepareOpts.SourceDir != sourceDir {
		t.Fatalf("prepare source dir = %q, want %q", prepareOpts.SourceDir, sourceDir)
	}
	if assets.RootfsPath == layout.RootfsPath {
		t.Fatalf("rootfs path = %q, want runtime copy instead of cache image", assets.RootfsPath)
	}
	if got, want := filepath.Base(assets.RootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("runtime rootfs base = %q, want %q", got, want)
	}
	if !filepath.IsAbs(assets.RootfsPath) {
		t.Fatalf("runtime rootfs path = %q, want absolute path", assets.RootfsPath)
	}
	data, err := os.ReadFile(assets.RootfsPath)
	if err != nil {
		t.Fatalf("ReadFile(runtime rootfs) error = %v", err)
	}
	if !bytes.Equal(data, cachedData) {
		t.Fatalf("runtime rootfs data = %q, want %q", data, cachedData)
	}
	if assets.WorkspacePath == "" {
		t.Fatal("workspace path should not be empty")
	}
}

func TestAssetPreparerFailsFastWhenRuntimeSpaceIsInsufficient(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tempDir, "run"))
	sourceDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Resources.RootDiskMB = 4096
	cfg.Resources.DiskMB = 1024

	writeCachedRootfsForRuntimeTest(t, cfg.ImageCacheDir, cfg.Image)

	workspacePrepared := false
	var runtimeDir string
	preparer := AssetPreparer{
		RuntimeFreeBytes: func(path string) (uint64, error) {
			runtimeDir = path
			return 512 * 1024 * 1024, nil
		},
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			workspacePrepared = true
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	_, err := preparer.Prepare(context.Background(), cfg, NopProgress{})
	if err == nil {
		t.Fatal("Prepare() error = nil, want insufficient runtime space error")
	}
	if !strings.Contains(err.Error(), "insufficient free space for runtime data") {
		t.Fatalf("Prepare() error = %v, want insufficient free space error", err)
	}
	if workspacePrepared {
		t.Fatal("workspace preparer should not run when runtime storage is insufficient")
	}
	if runtimeDir == "" {
		t.Fatal("runtime free-space check should capture a runtime dir")
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir %q should be removed after disk-pressure failure, stat err=%v", runtimeDir, err)
	}
	controlDirs, err := filepath.Glob(filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "keel", "vm-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(controlDirs) != 0 {
		t.Fatalf("control dirs = %#v, want none after disk-pressure failure", controlDirs)
	}
}

func TestAssetPreparerCleansUpEphemeralRuntimeDirWhenFeaturePreparationFails(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tempDir, "run"))
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Features = []config.FeatureConfig{{Name: "docker"}}
	writeCachedRootfsForRuntimeTest(t, cfg.ImageCacheDir, cfg.Image)

	var runtimeDir string
	preparer := AssetPreparer{
		RuntimeFreeBytes: func(string) (uint64, error) {
			return ^uint64(0), nil
		},
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, nil
		},
		PrepareFeatures: func(rootfsPath string, _ []config.FeatureConfig) error {
			runtimeDir = filepath.Dir(rootfsPath)
			return errors.New("feature prep failed")
		},
	}

	_, err := preparer.Prepare(context.Background(), cfg, NopProgress{})
	if err == nil || !strings.Contains(err.Error(), "feature prep failed") {
		t.Fatalf("Prepare() error = %v, want feature prep failure", err)
	}
	if runtimeDir == "" {
		t.Fatal("runtime dir should be captured")
	}
	controlDir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "keel")
	entries, err := filepath.Glob(filepath.Join(controlDir, "vm-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("control dirs under %q = %#v, want none", controlDir, entries)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir %q should be removed after feature prep failure, stat err=%v", runtimeDir, err)
	}
}

func TestAssetPreparerDefaultKernelResolutionPrefersKernelPath(t *testing.T) {
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

	writeCachedRootfsForRuntimeTest(t, tempDir, cfg.Image)

	assets, err := (AssetPreparer{
		RuntimeDir:        tempDir,
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if got, want := assets.KernelPath, kernelPath; got != want {
		t.Fatalf("assets.KernelPath = %q, want %q", got, want)
	}
}

func TestAssetPreparerPassesDefaultKernelSourceToResolution(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	writeCachedRootfsForRuntimeTest(t, tempDir, cfg.Image)

	var gotKernelCfg config.KernelConfig
	resolvedKernelPath := filepath.Join(tempDir, "resolved-vmlinux")
	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(_ context.Context, kernelCfg config.KernelConfig) (string, error) {
			gotKernelCfg = kernelCfg
			return resolvedKernelPath, nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
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

func TestAssetPreparerPassesKernelSourceToResolution(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Kernel.Source = "https://example.com/vmlinux"

	writeCachedRootfsForRuntimeTest(t, tempDir, cfg.Image)

	var gotKernelCfg config.KernelConfig
	resolvedKernelPath := filepath.Join(tempDir, "resolved-vmlinux")
	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(_ context.Context, kernelCfg config.KernelConfig) (string, error) {
			gotKernelCfg = kernelCfg
			return resolvedKernelPath, nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
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

func TestAssetPreparerPreparesVolumeAndMetadataAssets(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := t.TempDir()
	volumeDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = sourceDir
	cfg.Workspace.Target = "/workspace"
	cfg.RuntimeEnv = map[string]string{"TERM": "xterm-256color"}
	cfg.Features = []config.FeatureConfig{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver": "vfs",
		},
	}}
	cfg.Volumes = []config.VolumeConfig{{
		Source:    volumeDir,
		Target:    "/cache",
		Ownership: "host",
	}}

	writeCachedRootfsForRuntimeTest(t, cfg.ImageCacheDir, cfg.Image)

	var manifest pkgboot.Manifest
	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: stubWorkspacePrepare,
		VolumePreparer: func(opts volume.PrepareOptions) (volume.PrepareResult, error) {
			return volume.PrepareResult{ImagePath: opts.ImagePath, Kind: "dir"}, nil
		},
		WriteBootManifest: func(path string, item pkgboot.Manifest) error {
			manifest = item
			return os.WriteFile(path, []byte("meta"), 0o644)
		},
		GuestAssets:     emptyGuestAssets,
		PrepareFeatures: func(string, []config.FeatureConfig) error { return nil },
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
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
	if len(manifest.Features) != 1 || manifest.Features[0].Name != "docker" {
		t.Fatalf("manifest features = %#v, want docker feature", manifest.Features)
	}
	if got := manifest.Features[0].Config["storage_driver"]; got != "vfs" {
		t.Fatalf("manifest storage_driver = %#v, want vfs", got)
	}
}

func TestAssetPreparerReturnsGuestAssetLoadError(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	writeCachedRootfsForRuntimeTest(t, cfg.ImageCacheDir, cfg.Image)

	_, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		WorkspacePreparer: stubWorkspacePrepare,
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return image.GuestAgentAssets{}, errors.New("guest agent missing")
		},
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err == nil || !strings.Contains(err.Error(), "guest agent missing") {
		t.Fatalf("Prepare() error = %v, want guest asset load error", err)
	}
}

func TestAssetPreparerExpandsRuntimeRootfsWhenRootDiskConfigured(t *testing.T) {
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

	rootfsPath := writeCachedRootfsImageForRuntimeTest(t, tempDir, cfg.Image, rootfsSource, 2048)

	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if assets.RootfsPath == rootfsPath {
		t.Fatalf("RootfsPath = %q, want runtime copy distinct from cache rootfs", assets.RootfsPath)
	}
	info, err := os.Stat(assets.RootfsPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", assets.RootfsPath, err)
	}
	if got, want := info.Size(), int64(cfg.Resources.RootDiskMB)*1024*1024; got < want {
		t.Fatalf("runtime rootfs size = %d, want at least %d", got, want)
	}
}

func TestAssetPreparerRefreshesLegacyCachedRootfsWhenOCITarballExists(t *testing.T) {
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
	_, err = (AssetPreparer{
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
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if pullCalls != 1 {
		t.Fatalf("pullCalls = %d, want 1", pullCalls)
	}
}

func TestAssetPreparerAutoPullsMissingRootfs(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	var pulled bool
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")

	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
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
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if !pulled {
		t.Fatal("expected missing rootfs to trigger image pull")
	}
	if assets.RootfsPath == rootfsPath {
		t.Fatalf("RootfsPath = %q, want runtime copy distinct from pulled cache rootfs", assets.RootfsPath)
	}
	if got, want := filepath.Base(assets.RootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("runtime rootfs base = %q, want %q", got, want)
	}
}

func TestAssetPreparerRefreshesCachedGuestAgentWhenDigestChanges(t *testing.T) {
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
	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets: func() (image.GuestAgentAssets, error) {
			return guestAssets, nil
		},
		WorkspacePreparer: stubWorkspacePrepare,
		PrepareFeatures:   func(string, []config.FeatureConfig) error { return nil },
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if assets.RootfsPath == layout.RootfsPath {
		t.Fatalf("RootfsPath = %q, want runtime copy distinct from cache rootfs", assets.RootfsPath)
	}
	data, err := os.ReadFile(layout.AgentPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), guestAssets.Digest(); got != want {
		t.Fatalf("agent digest = %q, want %q", got, want)
	}
	if got := debugfsReadRuntime(t, assets.RootfsPath, "/usr/local/bin/keel-agent"); got != "agent-new" {
		t.Fatalf("runtime rootfs keel-agent = %q, want refreshed guest agent", got)
	}
}

func TestAssetPreparerInjectsMITMGuestTrustAssets(t *testing.T) {
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
	cfg.Network.Endpoints = []config.EndpointConfig{{
		Host: "api.github.com",
		Port: 443,
		MITM: &config.EndpointMITMConfig{Required: true},
	}}
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.MITM.CA.InstallSystem = true

	t.Setenv("HOME", tempDir)

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

	assets, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if got := debugfsReadRuntime(t, assets.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); got == "" {
		t.Fatal("expected injected mitm trust certificate")
	}
	if got := debugfsReadRuntime(t, assets.RootfsPath, "/etc/keel/install-ca.sh"); !strings.Contains(got, "update-ca-certificates") {
		t.Fatalf("install-ca.sh content = %q", got)
	}
	if got, ok := debugfsReadRuntimeIfPresent(t, layout.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); ok && got != "" {
		t.Fatal("cache rootfs should remain untouched by runtime guest trust injection")
	}
}

func TestAssetPreparerAppliesConfiguredFeatures(t *testing.T) {
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
	rootfsPath := writeCachedRootfsForRuntimeTest(t, tempDir, cfg.Image)

	_, err := (AssetPreparer{
		RuntimeDir: tempDir,
		EnsureKernel: func(context.Context, config.KernelConfig) (string, error) {
			return filepath.Join(tempDir, "vmlinux"), nil
		},
		GuestAssets:       emptyGuestAssets,
		WorkspacePreparer: stubWorkspacePrepare,
		PrepareFeatures: func(rootfsPath string, configured []config.FeatureConfig) error {
			gotRootfsPath = rootfsPath
			gotFeatures = append([]config.FeatureConfig(nil), configured...)
			return nil
		},
	}).Prepare(context.Background(), cfg, NopProgress{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
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

func TestAssetPreparerSyncMapsWorkspaceSyncBackOptions(t *testing.T) {
	cfg := config.Default()
	cfg.Workspace.Mount = "/host/workspace"
	cfg.Workspace.SyncBack = true
	cfg.Workspace.SyncDeletes = true
	cfg.Workspace.SyncConfirm = false
	stdin := strings.NewReader("confirm\n")
	stderr := io.Discard
	assets := vm.RuntimeAssets{WorkspacePath: "/runtime/workspace.ext4"}

	var got workspace.ImageSyncOptions
	err := (AssetPreparer{}).Sync(SyncRequest{
		Config: cfg,
		Stdin:  stdin,
		Stderr: stderr,
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			got = opts
			return workspace.SyncResult{Applied: true}, nil
		},
		SyncVolume: func(volume.SyncOptions) error {
			t.Fatal("volume sync should not run without volumes")
			return nil
		},
	}, assets)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got.HostDir != cfg.Workspace.Mount {
		t.Fatalf("HostDir = %q, want %q", got.HostDir, cfg.Workspace.Mount)
	}
	if got.ImagePath != assets.WorkspacePath {
		t.Fatalf("ImagePath = %q, want %q", got.ImagePath, assets.WorkspacePath)
	}
	if !got.SyncDeletes {
		t.Fatal("SyncDeletes = false, want true")
	}
	if got.Confirm {
		t.Fatal("Confirm = true, want false")
	}
	if got.In != stdin {
		t.Fatalf("In = %v, want stdin reader", got.In)
	}
	if got.Out != stderr {
		t.Fatalf("Out = %v, want stderr writer", got.Out)
	}
}

func TestAssetPreparerSyncDefaultsWorkspaceHostDir(t *testing.T) {
	cfg := config.Default()
	cfg.Workspace.Mount = ""
	cfg.Workspace.SyncBack = true
	assets := vm.RuntimeAssets{WorkspacePath: "/runtime/workspace.ext4"}

	var gotHostDir string
	err := (AssetPreparer{}).Sync(SyncRequest{
		Config: cfg,
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			gotHostDir = opts.HostDir
			return workspace.SyncResult{Applied: true}, nil
		},
	}, assets)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if gotHostDir != "." {
		t.Fatalf("HostDir = %q, want %q", gotHostDir, ".")
	}
}

func TestAssetPreparerSyncFiltersVolumes(t *testing.T) {
	cfg := config.Default()
	assets := vm.RuntimeAssets{
		Volumes: []vm.AttachedVolume{
			{
				SourcePath: "/host/cache",
				ImagePath:  "/runtime/cache.ext4",
				Kind:       "dir",
				Subpath:    "cache",
				SyncBack:   true,
			},
			{
				SourcePath: "/host/no-sync",
				ImagePath:  "/runtime/no-sync.ext4",
				Kind:       "dir",
				SyncBack:   false,
			},
			{
				SourcePath: "/host/read-only",
				ImagePath:  "/runtime/read-only.ext4",
				Kind:       "dir",
				SyncBack:   true,
				ReadOnly:   true,
			},
		},
	}

	var got []volume.SyncOptions
	err := (AssetPreparer{}).Sync(SyncRequest{
		Config: cfg,
		SyncWorkspace: func(workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			t.Fatal("workspace sync should not run when workspace sync_back is false")
			return workspace.SyncResult{}, nil
		},
		SyncVolume: func(opts volume.SyncOptions) error {
			got = append(got, opts)
			return nil
		},
	}, assets)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	want := []volume.SyncOptions{{
		SourcePath: "/host/cache",
		ImagePath:  "/runtime/cache.ext4",
		Kind:       "dir",
		Subpath:    "cache",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("volume sync options = %#v, want %#v", got, want)
	}
}

func TestAssetPreparerSyncPropagatesWorkspaceError(t *testing.T) {
	cfg := config.Default()
	cfg.Workspace.SyncBack = true
	wantErr := errors.New("workspace sync failed")

	err := (AssetPreparer{}).Sync(SyncRequest{
		Config: cfg,
		SyncWorkspace: func(workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			return workspace.SyncResult{}, wantErr
		},
		SyncVolume: func(volume.SyncOptions) error {
			t.Fatal("volume sync should not run after workspace sync failure")
			return nil
		},
	}, vm.RuntimeAssets{WorkspacePath: "/runtime/workspace.ext4", Volumes: []vm.AttachedVolume{{
		SourcePath: "/host/cache",
		ImagePath:  "/runtime/cache.ext4",
		SyncBack:   true,
	}}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Sync() error = %v, want %v", err, wantErr)
	}
}

func TestAssetPreparerSyncPropagatesVolumeError(t *testing.T) {
	cfg := config.Default()
	wantErr := errors.New("volume sync failed")

	err := (AssetPreparer{}).Sync(SyncRequest{
		Config: cfg,
		SyncVolume: func(volume.SyncOptions) error {
			return wantErr
		},
	}, vm.RuntimeAssets{Volumes: []vm.AttachedVolume{{
		SourcePath: "/host/cache",
		ImagePath:  "/runtime/cache.ext4",
		SyncBack:   true,
	}}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Sync() error = %v, want %v", err, wantErr)
	}
}

func emptyGuestAssets() (image.GuestAgentAssets, error) {
	return image.GuestAgentAssets{}, nil
}

func stubWorkspacePrepare(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
	return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
}

func writeCachedRootfsForRuntimeTest(t *testing.T, cacheDir, imageRef string) string {
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

func writeCachedRootfsImageForRuntimeTest(t *testing.T, cacheDir, imageRef, sourceDir string, sizeMB int) string {
	t.Helper()
	layout, err := image.ResolveCacheLayout(cacheDir, imageRef)
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.RootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if _, err := image.CreateRootfsImage(image.CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: layout.RootfsPath,
		SizeMB:    sizeMB,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}
	return layout.RootfsPath
}

func debugfsReadRuntime(t *testing.T, imagePath, target string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "debugfs", "-R", "cat "+target, imagePath)
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

func debugfsReadRuntimeIfPresent(t *testing.T, imagePath, target string) (string, bool) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "debugfs", "-R", "cat "+target, imagePath)
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
