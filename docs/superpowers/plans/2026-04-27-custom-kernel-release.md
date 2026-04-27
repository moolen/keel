# Custom Kernel Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and ship a Keel-managed custom Firecracker guest kernel with Docker-compatible netfilter support, publish it on releases, and make Keel resolve and cache release-managed kernel sources by default.

**Architecture:** Add a release-aware kernel resolver to the existing kernel manager and extend config with `kernel.source` while preserving `kernel.path` precedence. Build the custom kernel in release CI from the Firecracker baseline plus a small Keel-owned config fragment, then attach the kernel, checksum, and final config to each GitHub Release.

**Tech Stack:** Go, GitHub Actions, Linux kernel build tooling, Firecracker guest kernel config, GitHub Releases API, local cache metadata JSON.

---

### Task 1: Add kernel source config model

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader_test.go`
- Modify: `README.md`
- Modify: `keel.yaml.example`
- Test: `internal/config/loader_test.go`

- [ ] **Step 1: Write the failing config tests**

Add assertions that the loaded/default config exposes `kernel.source` and preserves `kernel.path` precedence.

```go
func TestDefaultConfigUsesReleaseManagedKernelSource(t *testing.T) {
	cfg := Default()
	if got, want := cfg.Kernel.Source, "release://latest"; got != want {
		t.Fatalf("cfg.Kernel.Source = %q, want %q", got, want)
	}
}

func TestLoadConfigReadsKernelSource(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keel.yaml")
	if err := os.WriteFile(configPath, []byte("kernel:\n  source: release://v0.2.0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: dir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.Kernel.Source, "release://v0.2.0"; got != want {
		t.Fatalf("cfg.Kernel.Source = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/config -run 'Test(DefaultConfigUsesReleaseManagedKernelSource|LoadConfigReadsKernelSource)'`

Expected: FAIL because `Kernel.Source` does not exist yet or defaults do not set it.

- [ ] **Step 3: Add `kernel.source` to config and defaults**

Update the config structs and defaults:

```go
type KernelConfig struct {
	Path   string `yaml:"path"`
	Source string `yaml:"source"`
}
```

```go
Kernel: KernelConfig{
	Path:   filepath.Join(home, ".cache", "keel", "kernel", "vmlinux"),
	Source: "release://latest",
},
```

Then remove any stale top-level `KernelPath` coupling that conflicts with this model if it is no longer needed by the loader.

- [ ] **Step 4: Update docs and example config**

Document:

```yaml
kernel:
  source: release://latest
```

Also document the supported forms:

- `path: /opt/keel/vmlinux`
- `source: release://latest`
- `source: release://v0.2.0`
- `source: https://...`

- [ ] **Step 5: Run config tests to verify they pass**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/config`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/defaults.go internal/config/loader_test.go README.md keel.yaml.example
git commit -m "feat: add kernel source config"
```

### Task 2: Add release-aware kernel source resolution and cache metadata

**Files:**
- Modify: `internal/vm/kernel.go`
- Create: `internal/vm/kernel_release.go`
- Create: `internal/vm/kernel_cache.go`
- Modify: `internal/vm/kernel_test.go`
- Create: `internal/vm/kernel_release_test.go`
- Test: `internal/vm/kernel_test.go`
- Test: `internal/vm/kernel_release_test.go`

- [ ] **Step 1: Write failing tests for release and URL sources**

Add table-driven tests covering:
- `kernel.path` direct use
- `release://latest` cache miss
- `release://latest` cache hit
- `release://latest` refresh on changed resolved tag
- `release://v0.2.0` immutable hit
- URL cache key stability
- release checksum mismatch

Example skeleton:

```go
func TestKernelManagerEnsureReleaseLatestCachesResolvedAsset(t *testing.T) {
	dir := t.TempDir()
	manager := KernelManager{
		CacheDir: dir,
		ResolveReleaseAsset: func(context.Context, string, string) (ReleaseKernelAsset, error) {
			return ReleaseKernelAsset{
				Tag:        "v0.2.0",
				KernelURL:  "https://example.invalid/keel-vmlinux-x86_64",
				SHA256URL:  "https://example.invalid/keel-vmlinux-x86_64.sha256",
				AssetName:  "keel-vmlinux-x86_64",
			}, nil
		},
		Download: stubDownload(...),
	}

	path, err := manager.EnsureSource(context.Background(), "release://latest")
	if err != nil {
		t.Fatalf("EnsureSource() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
}
```

- [ ] **Step 2: Run the kernel tests to verify they fail**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/vm -run 'TestKernelManager'`

Expected: FAIL because release-aware resolution and cache metadata do not exist yet.

- [ ] **Step 3: Add source-aware kernel manager entrypoints**

Introduce a resolver flow like:

```go
func (m KernelManager) Ensure(ctx context.Context, cfg config.KernelConfig) (string, error) {
	if cfg.Path != "" {
		return cfg.Path, validateKernelPath(cfg.Path)
	}
	source := cfg.Source
	if source == "" {
		source = "release://latest"
	}
	return m.ensureSource(ctx, source)
}
```

Keep the hypervisor-facing behavior unchanged: return a concrete local path.

- [ ] **Step 4: Add cache metadata and local layout helpers**

Create a small metadata type:

```go
type KernelCacheMetadata struct {
	SourceKind    string `json:"source_kind"`
	ResolvedTag   string `json:"resolved_tag,omitempty"`
	KernelURL     string `json:"kernel_url"`
	SHA256URL     string `json:"sha256_url,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	ETag          string `json:"etag,omitempty"`
	LastModified  string `json:"last_modified,omitempty"`
}
```

Add helpers for:
- `release-latest/<arch>/`
- `release-vX.Y.Z/<arch>/`
- `url-<hash>/<arch>/`

- [ ] **Step 5: Implement GitHub release asset resolution**

Add a tiny GitHub Releases client that can:
- fetch latest release
- fetch release by tag
- find:
  - `keel-vmlinux-x86_64`
  - optional `keel-vmlinux-x86_64.sha256`

Use the repo owner/name as a local constant in the resolver code.

- [ ] **Step 6: Implement download, verification, and revalidation**

Implement:
- immutable handling for `release://vX.Y.Z`
- mutable revalidation for `release://latest`
- URL revalidation using `ETag` / `Last-Modified` if present
- checksum verification for release assets before promoting temp files
- fail-open to cached `release://latest` on revalidation failure if the cache already exists

- [ ] **Step 7: Run the kernel test suite**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/vm`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/vm/kernel.go internal/vm/kernel_release.go internal/vm/kernel_cache.go internal/vm/kernel_test.go internal/vm/kernel_release_test.go
git commit -m "feat: resolve and cache release-managed kernels"
```

### Task 3: Wire host runner to the new kernel config

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`
- Test: `internal/cli/host_runner_test.go`

- [ ] **Step 1: Write failing host runner tests**

Add tests that prove:
- `kernel.path` wins when set
- default run uses `release://latest`
- `kernel.source` is passed into kernel resolution

Example:

```go
func TestHostRunnerUsesKernelPathOverride(t *testing.T) {
	cfg := config.Default()
	cfg.Kernel.Path = "/tmp/custom-vmlinux"
	cfg.Kernel.Source = "release://latest"

	var got config.KernelConfig
	runner := HostRunner{
		EnsureKernel: func(_ context.Context, kernelCfg config.KernelConfig) (string, error) {
			got = kernelCfg
			return kernelCfg.Path, nil
		},
	}
	// ... invoke run path ...
}
```

- [ ] **Step 2: Run host runner tests to verify they fail**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/cli -run 'TestHostRunner.*Kernel'`

Expected: FAIL because `EnsureKernel` still takes a raw string path.

- [ ] **Step 3: Change the `EnsureKernel` dependency shape**

Update `HostRunner.EnsureKernel` to accept the full kernel config:

```go
EnsureKernel func(context.Context, config.KernelConfig) (string, error)
```

And pass `cfg.Kernel` into it from `prepareAssets`.

- [ ] **Step 4: Update the default kernel manager call site**

Adapt the default manager so it resolves:

```go
kernelPath, err := ensureKernel(ctx, cfg.Kernel)
```

- [ ] **Step 5: Run host runner tests**

Run: `GOWORK=off /usr/local/go/bin/go test ./internal/cli`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go
git commit -m "refactor: route kernel config through host runner"
```

### Task 4: Add kernel config fragment and build script

**Files:**
- Create: `hack/kernel/firecracker-6.1-x86_64.config`
- Create: `hack/kernel/keel-netfilter.fragment`
- Create: `hack/kernel/build-kernel.sh`
- Create: `hack/kernel/README.md`
- Test: `hack/kernel/build-kernel.sh`

- [ ] **Step 1: Add the Keel kernel fragment**

Create a fragment enabling the Docker-relevant kernel features, for example:

```text
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=y
CONFIG_NF_NAT=y
CONFIG_NF_CONNTRACK=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_NAT=y
CONFIG_IP_NF_TARGET_MASQUERADE=y
CONFIG_BRIDGE=y
CONFIG_BRIDGE_NETFILTER=y
CONFIG_VETH=y
```

Include all direct prerequisites needed so `olddefconfig` yields the expected final config.

- [ ] **Step 2: Add the build script**

Create a script that:
- downloads or prepares Linux 6.1 source
- fetches the Firecracker baseline config
- applies the Keel fragment
- runs `olddefconfig`
- builds `vmlinux`
- emits:
  - kernel binary
  - merged `.config`
  - `.sha256`

Skeleton:

```bash
#!/usr/bin/env bash
set -euo pipefail

KERNEL_VERSION=6.1
ARCH=x86_64
OUT_DIR="${OUT_DIR:-$PWD/dist/kernel}"
SRC_DIR="${SRC_DIR:-$PWD/.cache/kernel-src/linux}"

# fetch source
# fetch firecracker baseline config
# merge config fragment
# make olddefconfig
# make -j"$(nproc)" vmlinux
# copy outputs
# sha256sum vmlinux > keel-vmlinux-x86_64.sha256
```

- [ ] **Step 3: Run the script locally in config-only or smoke mode**

Run a cheap mode first if provided, for example:

`hack/kernel/build-kernel.sh --config-only`

Expected: merged config produced successfully.

- [ ] **Step 4: Document the build inputs and outputs**

Add `hack/kernel/README.md` describing:
- baseline source config
- fragment purpose
- outputs
- local invocation

- [ ] **Step 5: Commit**

```bash
git add hack/kernel/firecracker-6.1-x86_64.config hack/kernel/keel-netfilter.fragment hack/kernel/build-kernel.sh hack/kernel/README.md
git commit -m "build: add custom firecracker kernel build assets"
```

### Task 5: Extend release CI to build and publish the kernel

**Files:**
- Modify: `.github/workflows/release.yml`
- Test: `.github/workflows/release.yml`

- [ ] **Step 1: Update the release workflow to build the kernel**

Add steps to:
- cache kernel build artifacts
- run `hack/kernel/build-kernel.sh`
- place outputs in `dist/release/`

Expected assets:
- `dist/release/keel-vmlinux-x86_64`
- `dist/release/keel-vmlinux-x86_64.sha256`
- `dist/release/keel-vmlinux-x86_64.config`

- [ ] **Step 2: Attach kernel assets to the GitHub Release**

Extend `gh release create` arguments to include:

```bash
dist/release/keel-vmlinux-x86_64 \
dist/release/keel-vmlinux-x86_64.sha256 \
dist/release/keel-vmlinux-x86_64.config
```

- [ ] **Step 3: Add workflow caching for efficiency**

Use GitHub Actions cache for:
- Linux source tree
- kernel build output dir
- ccache if introduced by the script

The cache key should include:
- kernel version
- baseline config identifier
- fragment file hash

- [ ] **Step 4: Validate workflow syntax**

Run: `yq '.' .github/workflows/release.yml >/dev/null`

Expected: exit 0

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: publish custom kernel release assets"
```

### Task 6: Update user-facing docs and cache behavior notes

**Files:**
- Modify: `README.md`
- Modify: `keel.yaml.example`
- Test: manual doc review

- [ ] **Step 1: Update the README kernel section**

Document:
- new default `release://latest`
- `kernel.path` override
- `kernel.source` supported forms
- local caching and mutable/immutable behavior

- [ ] **Step 2: Update examples**

Add examples for:

```yaml
kernel:
  source: release://latest
```

```yaml
kernel:
  source: release://v0.2.0
```

```yaml
kernel:
  path: /opt/keel/vmlinux
```

- [ ] **Step 3: Review docs for consistency**

Check that:
- release asset names match the workflow
- config names match the implementation
- default behavior no longer mentions the upstream Firecracker bucket as the primary path

- [ ] **Step 4: Commit**

```bash
git add README.md keel.yaml.example
git commit -m "docs: document release-managed kernel sources"
```

### Task 7: Final verification

**Files:**
- Modify: none
- Test: repo verification commands

- [ ] **Step 1: Run focused Go verification**

Run:

```bash
GOWORK=off /usr/local/go/bin/go test ./internal/config ./internal/vm ./internal/cli
```

Expected: PASS

- [ ] **Step 2: Run guest verification**

Run:

```bash
cd guest && /usr/local/go/bin/go test ./...
```

Expected: PASS

- [ ] **Step 3: Verify release workflow syntax**

Run:

```bash
yq '.' .github/workflows/release.yml >/dev/null
```

Expected: exit 0

- [ ] **Step 4: Verify kernel build script entrypoint**

Run:

```bash
hack/kernel/build-kernel.sh --help >/dev/null || true
```

If no `--help` mode exists, run the lightest supported validation/config-only mode instead and record the exact command.

- [ ] **Step 5: Final commit if needed**

```bash
git status --short
```

Commit any last documentation or test-fix changes with a focused message.
