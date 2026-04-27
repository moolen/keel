# Custom Kernel Release Design

## Goal

Ship a Keel-managed custom Firecracker guest kernel with netfilter and Docker-compatible networking enabled, publish it as part of the release process, cache it efficiently on hosts, and make it the default kernel source for Keel runs while still allowing explicit local paths and remote URLs.

## Scope

This design covers:

- the guest kernel build pipeline in CI
- release assets for the built kernel
- runtime kernel resolution and caching
- `keel.yaml` changes to support local paths and remote kernel sources

This design does not cover:

- multi-architecture kernel builds beyond the current `x86_64` target
- signed kernel release verification beyond SHA-256 asset checking
- replacing the existing guest agent or image distribution flow

## Requirements

- Start from Firecracker's `microvm-kernel-ci-x86_64-6.1.config`.
- Enable the netfilter, iptables, bridge, veth, and conntrack features needed for Docker bridge/NAT networking to work out of the box inside the guest.
- Build the kernel in CI and attach it to GitHub Releases.
- Make Keel default to a release-managed kernel instead of the upstream Firecracker bucket kernel.
- Allow users to override with either:
  - a local `kernel.path`
  - a remote `kernel.source`
- Support `kernel.source` as:
  - `release://latest`
  - `release://vX.Y.Z`
  - direct `https://...` URL
- Cache kernels locally and avoid repeated downloads.
- Revalidate mutable sources efficiently.

## Config Model

The runtime kernel configuration becomes:

```yaml
kernel:
  source: release://latest
```

Supported fields:

- `kernel.path`
  - exact local file path
  - if set, it takes precedence over everything else
- `kernel.source`
  - remote or release-managed source

Precedence:

1. `kernel.path`
2. `kernel.source`
3. default `kernel.source: release://latest`

Supported `kernel.source` forms:

- `release://latest`
- `release://v0.2.0`
- `https://github.com/.../keel-vmlinux-x86_64`

## Release Assets

Each GitHub Release publishes:

- `keel-vmlinux-x86_64`
- `keel-vmlinux-x86_64.sha256`
- `keel-vmlinux-x86_64.config`

The `.config` asset is the final merged kernel config actually used to build the kernel, not just the Firecracker baseline.

## Local Cache Layout

Kernel cache stays under the user's cache dir:

```text
~/.cache/keel/kernel/
  release-latest/
    x86_64/
      vmlinux
      metadata.json
  release-v0.2.0/
    x86_64/
      vmlinux
      metadata.json
  url-<hash>/
    x86_64/
      vmlinux
      metadata.json
```

`metadata.json` records:

- source kind
- resolved release tag when applicable
- asset URL
- sha256 URL when applicable
- stored sha256
- etag and/or last-modified if available

## Cache Semantics

### `kernel.path`

- no caching
- fail if the file does not exist or is unreadable

### `release://vX.Y.Z`

- immutable
- if cached, use it directly
- if missing, resolve that release and download once

### `release://latest`

- mutable
- resolve the latest GitHub Release metadata
- if the resolved tag matches cached metadata, reuse the cached kernel
- if the resolved tag changed, download the new asset and replace the cache entry
- if release resolution fails but a cached copy exists, fail open to the cached copy
- if release resolution fails and no cached copy exists, return an error

### direct URL

- cache under a stable hash of the source URL
- if `ETag` or `Last-Modified` is available, revalidate before redownloading
- otherwise treat the first successful download as stable until the cache is cleared

## Integrity Rules

- If a release-managed kernel has a `.sha256` asset, Keel verifies the downloaded kernel against it.
- A mismatch fails closed and does not promote the temporary file into cache.
- URL sources without a separate checksum are trusted only by transport integrity unless the server provides stable cache validators.

## CI Build Design

### Source Inputs

- Linux 6.1 source tarball or shallow git checkout
- Firecracker baseline config:
  - `resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config`
- a Keel-owned config fragment committed in this repo

### Keel Config Fragment

Keep the customization as a small fragment rather than a copied full config.

It enables the Docker-relevant networking features on top of the Firecracker baseline, including:

- `CONFIG_NETFILTER`
- `CONFIG_NF_TABLES`
- `CONFIG_NF_NAT`
- `CONFIG_NF_CONNTRACK`
- `CONFIG_BRIDGE`
- `CONFIG_BRIDGE_NETFILTER`
- `CONFIG_VETH`
- `CONFIG_IP_NF_IPTABLES`
- `CONFIG_IP_NF_FILTER`
- `CONFIG_IP_NF_NAT`
- `CONFIG_IP_NF_TARGET_MASQUERADE`
- `CONFIG_NETFILTER_XTABLES`
- other direct prerequisites required by Kconfig resolution

The CI build merges the Firecracker baseline and the Keel fragment, then runs `olddefconfig`.

### Build Outputs

The build job produces:

- `vmlinux`
- merged `.config`
- SHA-256 checksum file

### CI Efficiency

- Build only on `main`/release workflow, not every PR by default.
- Cache:
  - Linux source tree
  - compiler cache if practical
  - build output directories keyed by kernel version plus fragment hash
- PR CI can optionally validate fragment mergeability and config generation without a full release upload.

## Runtime Resolution Design

Replace the current upstream S3 kernel manager default path with a release-aware resolver.

Resolution flow:

1. If `kernel.path` is set, use it.
2. Else determine `kernel.source`, defaulting to `release://latest`.
3. Resolve source to a cached local path.
4. If cache miss or stale mutable source, download to a temp file in the kernel cache dir.
5. Verify checksum if available.
6. Atomically rename into cache.
7. Return the local path to the hypervisor layer.

The hypervisor continues to receive a plain local kernel path.

## GitHub Release Resolution

For `release://...`, Keel queries GitHub Releases for the current repo:

- latest release for `release://latest`
- specific tag for `release://vX.Y.Z`

It then selects the asset matching:

- `keel-vmlinux-x86_64`
- plus optional companion checksum asset

The repository owner/name should be a small constant in the kernel manager rather than inferred from unrelated config.

## Migration

- Existing `kernel.path` continues to work.
- Existing default behavior changes from “download upstream Firecracker kernel” to “download latest released Keel kernel”.
- Documentation and example config need to reflect the new default.

## Error Handling

Errors should clearly distinguish:

- local path missing
- GitHub release not found
- release asset missing for current arch
- checksum mismatch
- network failure while downloading
- stale cache fallback being used because revalidation failed

## Testing

Add tests for:

- config precedence: `path` over `source`
- `release://latest` cache hit and refresh
- `release://vX.Y.Z` immutable cache hit
- URL source cache identity and revalidation metadata
- checksum verification success and failure
- missing release asset failure
- latest-release resolution fallback to cached copy on network error

CI-side release workflow tests should validate:

- versioned release builds include kernel assets
- the asset names are stable
- the built config contains the expected netfilter and Docker networking options

## Recommended Implementation Order

1. Add `kernel.source` config support and defaults.
2. Extend the kernel manager to resolve release references and URLs into a local cache.
3. Add checksum verification and cache metadata.
4. Add the kernel config fragment and build scripts.
5. Extend the release workflow to build and attach kernel assets.
6. Update docs and example config.
