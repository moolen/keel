# Keel Kernel Build Tooling

This directory holds the committed inputs and helper script for the custom
Keel guest kernel build.

## Inputs

- `firecracker-6.1-x86_64.config`: vendored Firecracker guest kernel baseline
  for `x86_64` on the Linux 6.1 line (`microvm-kernel-ci-x86_64-6.1.config`).
- `keel-netfilter.fragment`: small Keel-owned delta enabling the extra nftables,
  iptables-compat, and vsock options the guest needs for transparent redirect
  and Docker-friendly networking.
- `build-kernel.sh`: cached, out-of-tree build entrypoint.

## What The Script Does

`./hack/kernel/build-kernel.sh` will:

1. Download the Linux `6.1.167` source tarball from `kernel.org` into
   `hack/kernel/.cache/`.
2. Extract the source tree once and reuse it across runs.
3. Start from the vendored Firecracker baseline config.
4. Merge the Keel fragment.
5. Run `olddefconfig`.
6. Build `vmlinux`.
7. Emit release-friendly artifacts into `hack/kernel/out/` by default.

Default outputs:

- `hack/kernel/out/vmlinux`
- `hack/kernel/out/vmlinux.config`
- `hack/kernel/out/vmlinux.sha256`

## Usage

Build the full kernel:

```bash
./hack/kernel/build-kernel.sh
```

Run the cheap config-only path:

```bash
./hack/kernel/build-kernel.sh --config-only
```

Useful overrides:

```bash
OUT_DIR=/tmp/keel-kernel-out ./hack/kernel/build-kernel.sh
ARTIFACT_BASENAME=keel-vmlinux-x86_64 ./hack/kernel/build-kernel.sh
JOBS=8 ./hack/kernel/build-kernel.sh
```

## Notes

- The build is intentionally out-of-tree so the cached source tree can be
  reused cleanly in CI.
- The output basename is configurable now so Task 5 can publish release assets
  without changing the build logic.
- `hack/kernel/build.sh` remains as a compatibility shim for older local entry
  points, but `build-kernel.sh` is the canonical script.
