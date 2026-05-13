# Codebase Architecture Deepening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deepen Keel's runtime, network, ext4, and feature modules while preserving current CLI and VM behavior.

**Architecture:** Execute the refactor as staged vertical slices. First extract runtime asset materialization from `HostRunner`, then extract network service wiring, then centralize ext4 image operations, then simplify `HostRunner`, then clarify feature contracts. Each slice introduces a focused module interface and migrates only the tests that belong to that interface.

**Tech Stack:** Go, Firecracker/vsock, ext4 image tooling (`truncate`, `mkfs.ext4`, `debugfs`, `mount`), existing Keel `internal/config`, `internal/vm`, `internal/network`, `internal/image`, `internal/workspace`, `internal/volume`, and `guest/internal/features` packages.

---

## Baseline And Constraints

The design was written in an environment where `go` was not on `PATH`. Before executing this plan, establish a Go-capable baseline:

```bash
command -v go
go test ./...
```

Expected: `command -v go` prints a Go binary path and `go test ./...` passes. If Go is installed outside `PATH`, use the local path consistently for all commands, for example:

```bash
/usr/local/go/bin/go test ./...
```

If baseline tests fail before any code changes, stop and report the failures before continuing.

## File Structure

Create and modify these files over the full plan:

- Create: `internal/runtime/assets.go`
  Owns runtime asset materialization from `config.Config` to `vm.RuntimeAssets`.
- Create: `internal/runtime/assets_test.go`
  Focused tests for runtime asset preparation.
- Create: `internal/runtime/network.go`
  Owns network service construction and startup for Unix socket and VM listener modes.
- Create: `internal/runtime/network_test.go`
  Focused tests for network service construction and startup behavior.
- Create: `internal/ext4/image.go`
  Owns ext4 image creation, sparse copy, debugfs mutation, and mount helpers.
- Create: `internal/ext4/image_test.go`
  Focused tests for ext4 behavior that can run without privileged mounts where possible.
- Modify: `internal/cli/host_runner.go`
  Shrink `HostRunner` to runtime orchestration and adapters.
- Modify: `internal/cli/host_runner_test.go`
  Remove tests that now belong to `internal/runtime`; keep runner orchestration tests.
- Modify: `internal/workspace/prepare.go`
  Delegate ext4 image creation to `internal/ext4`.
- Modify: `internal/workspace/sync.go`
  Delegate image mounting to `internal/ext4`.
- Modify: `internal/volume/prepare.go`
  Keep volume semantics, delegate image creation through workspace/ext4.
- Modify: `internal/volume/sync.go`
  Delegate image mounting to `internal/ext4`.
- Modify: `internal/image/convert.go`
  Delegate ext4 rootfs image creation to `internal/ext4` while preserving rootfs size estimation semantics.
- Modify: `internal/image/inject.go`
  Delegate debugfs helpers to `internal/ext4`.
- Modify: `internal/bootmanifest/image.go`
  Continue manifest encoding, relying on workspace/ext4 image creation.
- Modify: `internal/features/registry.go`
  Add a typed feature preparation seam without changing user-facing feature config.
- Modify: `internal/features/docker.go`
  Make Docker host-side defaults and validation explicit.
- Modify: `guest/internal/features/docker.go`
  Keep guest behavior, but align Docker config defaulting with host-side contract.

## Task 0: Worktree And Baseline

**Files:**
- No code files.

- [ ] **Step 1: Create or enter an isolated worktree**

Use the `superpowers:using-git-worktrees` skill. If no native worktree tool is available, create a project-local worktree under `.worktrees/architecture-deepening` after verifying `.worktrees` is ignored:

```bash
git check-ignore -q .worktrees
git worktree add .worktrees/architecture-deepening -b architecture-deepening
cd .worktrees/architecture-deepening
```

Expected: the command creates a clean worktree on branch `architecture-deepening`.

- [ ] **Step 2: Verify Go baseline**

Run:

```bash
command -v go
go test ./...
```

Expected: `go` is found and all tests pass. If `go` is not found, locate the Go binary and rerun with its absolute path. If tests fail, stop and report the baseline failure.

## Task 1: Extract Runtime Asset Materialization

**Files:**
- Create: `internal/runtime/assets.go`
- Create: `internal/runtime/assets_test.go`
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`

- [ ] **Step 1: Write the failing runtime asset test**

Create `internal/runtime/assets_test.go` with a test that captures the desired module interface. Start with this test:

```go
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/workspace"
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
	if err := os.WriteFile(layout.RootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
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
		t.Fatalf("workspace source = %q, want %q", prepareOpts.SourceDir, sourceDir)
	}
	if assets.RootfsPath == layout.RootfsPath {
		t.Fatalf("rootfs path = %q, want runtime copy instead of cache image", assets.RootfsPath)
	}
	if got, want := filepath.Base(assets.RootfsPath), "rootfs.ext4"; got != want {
		t.Fatalf("runtime rootfs base = %q, want %q", got, want)
	}
	if !strings.HasPrefix(assets.RootfsPath, tempDir) {
		t.Fatalf("runtime rootfs path = %q, want path under %q", assets.RootfsPath, tempDir)
	}
	if assets.WorkspacePath == "" {
		t.Fatal("workspace path should not be empty")
	}
}

func TestAssetPreparerReturnsRuntimeAssets(t *testing.T) {
	var _ vm.RuntimeAssets
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./internal/runtime -run TestAssetPreparerCopiesCachedRootfsIntoRuntimeAssets -count=1
```

Expected: FAIL because `internal/runtime` and `AssetPreparer` do not exist.

- [ ] **Step 3: Implement the minimal runtime asset module**

Create `internal/runtime/assets.go`. Move the asset-preparation types and logic out of `internal/cli/host_runner.go` into this package. Use these public names:

```go
package runtime

import (
	"context"
	"io"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

type Progress interface {
	Step(ProgressStep)
}

type ProgressStep struct {
	Index   int
	Total   int
	Title   string
	Detail  string
	Current int64
	Target  int64
	Done    bool
}

type NopProgress struct{}

func (NopProgress) Step(ProgressStep) {}

type AssetPreparer struct {
	RuntimeDir        string
	RuntimeFreeBytes  func(string) (uint64, error)
	EnsureKernel      func(context.Context, config.KernelConfig) (string, error)
	GuestAssets       func() (image.GuestAgentAssets, error)
	WorkspacePreparer func(workspace.PrepareOptions) (workspace.PrepareResult, error)
	VolumePreparer    func(volume.PrepareOptions) (volume.PrepareResult, error)
	WriteBootManifest func(string, pkgboot.Manifest) error
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	PrepareFeatures   func(string, []config.FeatureConfig) error
}

func (p AssetPreparer) Prepare(ctx context.Context, cfg config.Config, progress Progress) (vm.RuntimeAssets, error)
func (p AssetPreparer) Sync(req SyncRequest, assets vm.RuntimeAssets) error

type SyncRequest struct {
	Config        config.Config
	Stdin         io.Reader
	Stderr        io.Writer
	SyncWorkspace func(workspace.ImageSyncOptions) (workspace.SyncResult, error)
	SyncVolume    func(volume.SyncOptions) error
}
```

Implement `Prepare` by moving the existing `HostRunner.prepareAssets` body. Implement `Sync` by moving the existing `HostRunner.syncWorkspace` body. Keep private helpers in `internal/runtime/assets.go` for now: `copyRuntimeRootfs`, `ensureRuntimeCapacity`, `estimateRuntimeDataRequirement`, `runtimeFreeBytes`, `ensureRuntimeRootfsSize`, `buildBootManifest`, `cloneStringMap`, and volume preparation.

Move only the code needed for asset materialization and sync-back. Leave VM handoff, PTY behavior, progress UI formatting, and attach-failure diagnosis in `cli`.

- [ ] **Step 4: Adapt `HostRunner` to call `runtime.AssetPreparer`**

In `internal/cli/host_runner.go`, import the runtime package with an alias to avoid confusion with the standard library:

```go
keelruntime "github.com/moolen/keel/internal/runtime"
```

Add this field to `HostRunner`:

```go
PrepareAssets func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error)
```

Replace the direct `r.prepareAssets(ctx, cfg, progress)` call with:

```go
prepareAssets := r.PrepareAssets
if prepareAssets == nil {
	preparer := keelruntime.AssetPreparer{
		RuntimeDir:        r.RuntimeDir,
		RuntimeFreeBytes:  r.RuntimeFreeBytes,
		EnsureKernel:      r.EnsureKernel,
		GuestAssets:       r.GuestAssets,
		WorkspacePreparer: r.WorkspacePreparer,
		VolumePreparer:    r.VolumePreparer,
		WriteBootManifest: r.WriteBootManifest,
		PullImage:         r.PullImage,
		PrepareFeatures:   r.PrepareFeatures,
	}
	prepareAssets = preparer.Prepare
}
assets, err := prepareAssets(ctx, cfg, runtimeProgressAdapter{progress})
```

Add a small adapter in `cli` that maps `keelruntime.ProgressStep` into the existing `startupStep`. During the first extraction, the adapter can map only `Title`, `Detail`, `Index`, and `Total`; preserve detailed kernel/image progress in a later cleanup if needed.

- [ ] **Step 5: Move focused tests**

Move these tests from `internal/cli/host_runner_test.go` into `internal/runtime/assets_test.go`, updating names and receiver setup to use `AssetPreparer`:

- `TestHostRunnerPreparesAssetsBeforeLaunch`
- `TestHostRunnerExpandsRuntimeRootfsWhenRootDiskConfigured`
- `TestHostRunnerFailsFastWhenRuntimeSpaceIsInsufficient`
- `TestHostRunnerCleansUpEphemeralRuntimeDirWhenFeaturePreparationFails`
- `TestCopyRuntimeRootfsPreservesSparseFiles`
- kernel resolution tests that call `prepareAssets`
- cached rootfs refresh tests that call `prepareAssets`
- guest asset load failure tests that call `prepareAssets`

Keep `TestHostRunnerDryRunPrintsSummary`, PTY tests, VM handoff tests, and sync confirmation tests in `internal/cli`.

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./internal/runtime ./internal/cli -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/runtime/assets.go internal/runtime/assets_test.go internal/cli/host_runner.go internal/cli/host_runner_test.go
git commit -m "refactor: extract runtime asset preparation"
```

## Task 2: Extract Network Runtime Wiring

**Files:**
- Create: `internal/runtime/network.go`
- Create: `internal/runtime/network_test.go`
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`

- [ ] **Step 1: Write the failing network runtime test**

Create `internal/runtime/network_test.go`:

```go
package runtime

import (
	"context"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/network"
)

func TestNetworkServicesBuildEndpointScopedPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Endpoints = []config.EndpointConfig{{
		Host: "api.github.com",
		Port: 443,
		TLS:  &config.EndpointTLSConfig{RequireSNIMatch: true},
		MITM: &config.EndpointMITMConfig{Required: true},
		HTTP: &config.EndpointHTTPConfig{
			Default: "deny",
			Rules: []config.EndpointHTTPRuleConfig{{
				Action:  "allow",
				Methods: []string{"GET"},
				Paths:   []string{"/repos/*"},
			}},
		},
	}}

	factory := NetworkServiceFactory{
		LoadMITMCA: func(config.Config) (*network.CA, error) {
			return &network.CA{CertPEM: []byte("test-ca")}, nil
		},
	}
	services, err := factory.Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if services.Summary == nil {
		t.Fatal("Summary = nil, want non-nil")
	}
	if services.DNS.Policy == nil || services.TCP.Policy == nil {
		t.Fatal("proxies should share a policy engine")
	}
	if services.TCP.MITM == nil {
		t.Fatal("TCP MITM = nil, want MITM when endpoint requires it")
	}
}

func TestNetworkServicesCanBeStoppedWithoutStart(t *testing.T) {
	stop := NetworkStopFunc(func() {})
	stop()
	_ = context.Background()
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./internal/runtime -run TestNetworkServicesBuildEndpointScopedPolicy -count=1
```

Expected: FAIL because `NetworkServiceFactory` does not exist.

- [ ] **Step 3: Implement network service factory**

Create `internal/runtime/network.go` with these public types:

```go
package runtime

import (
	"context"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/vm"
)

type NetworkServices struct {
	DNS     network.DNSProxy
	TCP     network.TCPProxy
	Summary *network.Summary
}

type NetworkStopFunc func()

type NetworkServiceFactory struct {
	EventOutput EventWriter
	LoadMITMCA  func(config.Config) (*network.CA, error)
}

type EventWriter interface {
	Write([]byte) (int, error)
}

func (f NetworkServiceFactory) Build(cfg config.Config) (NetworkServices, error)
func (f NetworkServiceFactory) StartUnix(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (NetworkStopFunc, *network.Summary, error)
func (f NetworkServiceFactory) StartVM(ctx context.Context, cfg config.Config, instance hypervisor.VM) (NetworkStopFunc, *network.Summary, error)
```

Implement these methods by moving behavior from `cli`: `Build` receives the existing `buildNetworkServices` body, `StartUnix` receives the existing `HostRunner.startServices` body, and `StartVM` receives the existing `HostRunner.startVMServices` body. Move config-to-policy helpers into this file: `endpointRulesFromConfig`, `endpointHTTPPolicyFromConfig`, `endpointHTTPRulesFromConfig`, `ipRulesFromConfig`, and `policyRequiresMITM`.

The default `LoadMITMCA` implementation should preserve the current CA path:

```go
home, err := os.UserHomeDir()
caDir := filepath.Join(home, ".local", "share", "keel", "ca")
network.LoadOrCreateCA(network.CAOptions{Dir: caDir, Name: cfg.Network.MITM.CA.Name})
```

- [ ] **Step 4: Adapt `HostRunner` to call network runtime**

In `internal/cli/host_runner.go`, remove `buildNetworkServices`, `endpointRulesFromConfig`, `endpointHTTPPolicyFromConfig`, `endpointHTTPRulesFromConfig`, `ipRulesFromConfig`, `policyRequiresMITM`, and `loadMITMCA` after moving them.

Replace `r.startServices` and `r.startVMServices` calls with `keelruntime.NetworkServiceFactory{}.StartUnix` and `StartVM`.

Keep `ServiceStarter` injection in `HostRunner` for orchestration tests, but make the default implementation delegate to `NetworkServiceFactory`.

- [ ] **Step 5: Move network tests**

Move these tests from `internal/cli/host_runner_test.go` to `internal/runtime/network_test.go`, updating package and call sites:

- tests that call `buildNetworkServices`
- tests that call `startVMServices`
- tests around MITM service construction

Keep any runner test that asserts `HostRunner` prints the summary after a run.

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./internal/runtime ./internal/cli ./internal/network -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/runtime/network.go internal/runtime/network_test.go internal/cli/host_runner.go internal/cli/host_runner_test.go
git commit -m "refactor: extract runtime network services"
```

## Task 3: Introduce Ext4 Image Operations Module

**Files:**
- Create: `internal/ext4/image.go`
- Create: `internal/ext4/image_test.go`
- Modify: `internal/workspace/prepare.go`
- Modify: `internal/workspace/sync.go`
- Modify: `internal/volume/sync.go`
- Modify: `internal/image/convert.go`
- Modify: `internal/image/inject.go`
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/runtime/assets.go`

- [ ] **Step 1: Write the failing sparse-copy test**

Create `internal/ext4/image_test.go`:

```go
package ext4

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCopySparseFilePreservesLogicalSize(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.ext4")
	targetPath := filepath.Join(tempDir, "target.ext4")

	src, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
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
	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := CopySparseFile(sourcePath, targetPath); err != nil {
		t.Fatalf("CopySparseFile() error = %v", err)
	}
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatalf("Stat(source) error = %v", err)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if targetInfo.Size() != sourceInfo.Size() {
		t.Fatalf("target size = %d, want %d", targetInfo.Size(), sourceInfo.Size())
	}
	sourceBlocks := statBlocks(t, sourceInfo)
	targetBlocks := statBlocks(t, targetInfo)
	if sourceBlocks > 0 && targetBlocks > sourceBlocks*4 {
		t.Fatalf("target blocks = %d, want close to source blocks %d", targetBlocks, sourceBlocks)
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./internal/ext4 -run TestCopySparseFilePreservesLogicalSize -count=1
```

Expected: FAIL because `internal/ext4` and `CopySparseFile` do not exist.

- [ ] **Step 3: Implement ext4 module**

Create `internal/ext4/image.go` with these public functions:

```go
package ext4

type CreateOptions struct {
	SourceDir string
	ImagePath string
	SizeMB    int
	Label     string
}

type CreateResult struct {
	ImagePath  string
	SizeBytes  int64
}

func CreateImage(opts CreateOptions) (CreateResult, error)
func CopySparseFile(sourcePath, targetPath string) error
func GrowImage(imagePath string, minSizeMB int) error
func MountReadOnly(imagePath, tempPattern string, allowJournalRecovery bool) (string, func(), error)
func EnsureDirs(imagePath string, dirs ...string) error
func WriteFile(imagePath, targetPath, sourcePath string) error
func RemoveFile(imagePath, targetPath string) error
func ReadFile(imagePath, targetPath string) ([]byte, error)
```

Move the existing implementations from:

- `workspace.PrepareImage` for `CreateImage`
- `HostRunner.copyRuntimeRootfs` for `CopySparseFile`
- `HostRunner.ensureRuntimeRootfsSize` for `GrowImage`
- `workspace.mountImageReadOnly` and `volume.mountImageReadOnly` for `MountReadOnly`
- `image.inject.go` debugfs helpers for debugfs functions

Preserve error messages closely enough that existing tests still pass, updating tests only where package names changed.

- [ ] **Step 4: Migrate callers**

Update callers:

- `internal/workspace/prepare.go`: call `ext4.CreateImage`.
- `internal/workspace/sync.go`: call `ext4.MountReadOnly(opts.ImagePath, "keel-workspace-mount-*", true)`.
- `internal/volume/sync.go`: call `ext4.MountReadOnly(opts.ImagePath, "keel-volume-mount-*", false)`.
- `internal/image/convert.go`: keep rootfs size estimation, then call `ext4.CreateImage`.
- `internal/image/inject.go`: call `ext4.EnsureDirs`, `ext4.WriteFile`, `ext4.RemoveFile`, and `ext4.ReadFile`.
- `internal/runtime/assets.go`: call `ext4.CopySparseFile` and `ext4.GrowImage`.

- [ ] **Step 5: Move sparse-copy test**

Remove `TestCopyRuntimeRootfsPreservesSparseFiles` from `internal/cli/host_runner_test.go` or `internal/runtime/assets_test.go` after the equivalent `internal/ext4` test is passing.

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./internal/ext4 ./internal/workspace ./internal/volume ./internal/image ./internal/runtime -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/ext4/image.go internal/ext4/image_test.go internal/workspace/prepare.go internal/workspace/sync.go internal/volume/sync.go internal/image/convert.go internal/image/inject.go internal/runtime/assets.go internal/runtime/assets_test.go internal/cli/host_runner_test.go
git commit -m "refactor: centralize ext4 image operations"
```

## Task 4: Simplify HostRunner Orchestration

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`
- Modify: `internal/runtime/assets.go`
- Modify: `internal/runtime/network.go`

- [ ] **Step 1: Write the failing runner orchestration test**

Add this test to `internal/cli/host_runner_test.go`:

```go
func TestHostRunnerDelegatesRuntimePreparationAndNetworkStartup(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.Workspace.Mount = t.TempDir()

	var prepared bool
	var startedServices bool
	var ranMachine bool
	assets := runtimeAssetsForHostRunnerVMTest(t, t.TempDir())

	runner := HostRunner{
		PrepareAssets: func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
			prepared = true
			return assets, nil
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			startedServices = true
			return func() {}, network.NewSummary(), nil
		},
		MachineFactory: func(config.Config, vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{run: func(context.Context) error {
				ranMachine = true
				return nil
			}}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !prepared || !startedServices || !ranMachine {
		t.Fatalf("delegation prepared=%v services=%v ran=%v", prepared, startedServices, ranMachine)
	}
}
```

If `stubMachineRunner` does not yet accept a run function, extend it in the test file:

```go
type stubMachineRunner struct {
	run func(context.Context) error
}

func (s stubMachineRunner) Run(ctx context.Context) error {
	if s.run != nil {
		return s.run(ctx)
	}
	return nil
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./internal/cli -run TestHostRunnerDelegatesRuntimePreparationAndNetworkStartup -count=1
```

Expected: FAIL until `HostRunner` exposes and uses the narrower delegation points.

- [ ] **Step 3: Remove migrated helpers from `HostRunner`**

Delete from `internal/cli/host_runner.go` any helper now owned by `internal/runtime` or `internal/ext4`, including:

- runtime asset preparation helpers
- network policy conversion helpers
- network service startup helpers
- rootfs sparse copy helpers
- ext4 growth helpers
- volume preparation helpers if fully moved into runtime assets
- boot manifest construction helpers if fully moved into runtime assets

Keep:

- `Run`
- `runPreparedVM`
- `diagnoseAttachFailure`
- `forwardedPTYStdin`
- progress UI helpers
- `warnNetworkAuditMode`
- `printNetworkSummary`
- dry-run behavior
- runtime config resolution until Task 5 moves feature config defaulting

- [ ] **Step 4: Run focused tests**

Run:

```bash
go test ./internal/cli ./internal/runtime -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go internal/runtime/assets.go internal/runtime/network.go
git commit -m "refactor: simplify host runner orchestration"
```

## Task 5: Clarify Feature Contract

**Files:**
- Modify: `internal/features/registry.go`
- Modify: `internal/features/docker.go`
- Modify: `internal/features/docker_test.go`
- Modify: `internal/runtime/assets.go`
- Modify: `guest/internal/features/docker.go`
- Modify: `guest/internal/features/docker_test.go`

- [ ] **Step 1: Write the failing host feature config test**

Add this test to `internal/features/docker_test.go`:

```go
func TestDockerFeatureNormalizesConfig(t *testing.T) {
	feature := NewDockerFeature()
	cfg, err := feature.NormalizeConfig(map[string]any{
		"registry_mirrors": []any{"https://mirror.example"},
	})
	if err != nil {
		t.Fatalf("NormalizeConfig() error = %v", err)
	}
	if cfg.Name != "docker" {
		t.Fatalf("Name = %q, want docker", cfg.Name)
	}
	if got := cfg.Config["storage_driver"]; got != "vfs" {
		t.Fatalf("storage_driver = %#v, want vfs", got)
	}
	if got := cfg.Config["registry_mirrors"]; got == nil {
		t.Fatal("registry_mirrors missing from normalized config")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./internal/features -run TestDockerFeatureNormalizesConfig -count=1
```

Expected: FAIL because `NormalizeConfig` does not exist.

- [ ] **Step 3: Add normalized feature contract**

Update `internal/features/registry.go`:

```go
type NormalizedFeature struct {
	Name   string
	Config map[string]any
}

type Feature interface {
	Name() string
	ValidateConfig(map[string]any) error
	NormalizeConfig(map[string]any) (NormalizedFeature, error)
	PrepareRootfs(string, map[string]any) error
}

func (r *Registry) Normalize(configured []ConfiguredFeature) ([]NormalizedFeature, error) {
	items := make([]NormalizedFeature, 0, len(configured))
	for _, item := range configured {
		feature, ok := r.features[item.Name]
		if !ok {
			return nil, fmt.Errorf("unknown feature %q (available: %v)", item.Name, r.Names())
		}
		normalized, err := feature.NormalizeConfig(item.Config)
		if err != nil {
			return nil, fmt.Errorf("feature %q: %w", item.Name, err)
		}
		items = append(items, normalized)
	}
	return items, nil
}
```

Update `DockerFeature.NormalizeConfig` to parse `DockerConfig`, apply `StorageDriver: "vfs"` when omitted, and return a plain map that can still be JSON encoded for the guest.

- [ ] **Step 4: Use normalization in runtime feature config**

In `internal/runtime/assets.go` or the remaining runtime config code, replace ad hoc Docker config mutation with:

1. Build the feature registry.
2. Normalize configured features.
3. If MITM CA must be installed for Docker, add `mitm_ca_pem` to the normalized Docker config.
4. Convert normalized features back to `[]config.FeatureConfig` for existing kernel/manifest transport.

Keep the public config YAML unchanged.

- [ ] **Step 5: Align guest Docker defaults**

In `guest/internal/features/docker.go`, keep `DockerConfig{StorageDriver: "vfs"}` as the default. Add or update a test in `guest/internal/features/docker_test.go` that verifies an omitted storage driver still writes `"storage-driver":"vfs"` to `/etc/docker/daemon.json`.

- [ ] **Step 6: Run focused tests**

Run:

```bash
go test ./internal/features ./internal/runtime ./guest/internal/features -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/features/registry.go internal/features/docker.go internal/features/docker_test.go internal/runtime/assets.go guest/internal/features/docker.go guest/internal/features/docker_test.go
git commit -m "refactor: normalize feature configuration"
```

## Task 6: Final Verification And Documentation Pass

**Files:**
- Modify only if tests reveal required doc updates: `README.md`, `keel.yaml.example`

- [ ] **Step 1: Run full test suite**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 2: Run static checks if available**

Run:

```bash
make test
```

Expected: PASS, or report if the Makefile target requires unavailable host tools.

- [ ] **Step 3: Inspect final `HostRunner` size and responsibilities**

Run:

```bash
wc -l internal/cli/host_runner.go internal/runtime/assets.go internal/runtime/network.go internal/ext4/image.go
rg -n "func \\(r HostRunner\\) prepareAssets|func buildNetworkServices|func copyRuntimeRootfs|func ensureRuntimeCapacity" internal/cli/host_runner.go
```

Expected: `host_runner.go` is materially smaller than before, and the `rg` command finds none of the migrated helper functions in `internal/cli/host_runner.go`.

- [ ] **Step 4: Confirm no behavior docs need changes**

Run:

```bash
git diff -- README.md keel.yaml.example
```

Expected: no diff required, because this plan preserves CLI and config behavior. If implementation changed user-visible behavior, stop and either revert that behavior change or update docs explicitly.

- [ ] **Step 5: Commit final documentation updates if needed**

If docs changed:

```bash
git add README.md keel.yaml.example
git commit -m "docs: update architecture refactor notes"
```

If docs did not change, do not create an empty commit.

## Self-Review Checklist

- Runtime asset materialization is behind `internal/runtime.AssetPreparer`.
- Network service construction and startup are behind `internal/runtime.NetworkServiceFactory`.
- Ext4 operational behavior is centralized in `internal/ext4`.
- `HostRunner` no longer owns asset preparation, network construction, rootfs copying, or ext4 debugfs helpers.
- Docker feature config has one host-side normalization path and guest-side defaults stay compatible.
- Public CLI behavior, config schema, network policy semantics, and VM boot behavior are unchanged.
- Focused package tests and `go test ./...` pass in a Go-capable environment.
