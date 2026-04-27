#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: hack/kernel/build-kernel.sh [--config-only] [--help]

Build the Keel release kernel from the Firecracker 6.1 x86_64 baseline plus
the local Keel netfilter fragment.

Options:
  --config-only  Merge configs and run olddefconfig, but do not build vmlinux.
  --help         Show this help text.

Environment:
  KERNEL_VERSION     Linux version to build (default: 6.1.167)
  ARCH               Guest architecture (default: x86_64)
  JOBS               Parallel make jobs (default: detected CPU count)
  CACHE_DIR          Download/build cache root (default: hack/kernel/.cache)
  SRC_DIR            Extracted Linux source dir (default: CACHE_DIR/linux-<ver>)
  BUILD_DIR          Out-of-tree kernel build dir
  OUT_DIR            Output artifact dir (default: hack/kernel/out)
  ARTIFACT_BASENAME  Output filename prefix (default: vmlinux)
  BASELINE_CONFIG    Baseline kernel config file
  FRAGMENT_CONFIG    Keel fragment config file
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
  done
}

cpu_count() {
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null && return 0
  fi
  if command -v nproc >/dev/null 2>&1; then
    nproc && return 0
  fi
  echo 1
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

KERNEL_VERSION=${KERNEL_VERSION:-6.1.167}
ARCH=${ARCH:-x86_64}
JOBS=${JOBS:-$(cpu_count)}
CACHE_DIR=${CACHE_DIR:-"$SCRIPT_DIR/.cache"}
SRC_DIR=${SRC_DIR:-"$CACHE_DIR/linux-$KERNEL_VERSION"}
BUILD_DIR=${BUILD_DIR:-"$CACHE_DIR/build-$ARCH-$KERNEL_VERSION"}
OUT_DIR=${OUT_DIR:-"$SCRIPT_DIR/out"}
ARTIFACT_BASENAME=${ARTIFACT_BASENAME:-vmlinux}
BASELINE_CONFIG=${BASELINE_CONFIG:-"$SCRIPT_DIR/firecracker-6.1-x86_64.config"}
FRAGMENT_CONFIG=${FRAGMENT_CONFIG:-"$SCRIPT_DIR/keel-netfilter.fragment"}
KERNEL_TARBALL=${KERNEL_TARBALL:-"$CACHE_DIR/linux-$KERNEL_VERSION.tar.xz"}
KERNEL_TARBALL_URL=${KERNEL_TARBALL_URL:-"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"}

CONFIG_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config-only)
      CONFIG_ONLY=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

[[ "$ARCH" == "x86_64" ]] || die "unsupported ARCH: $ARCH"
[[ -f "$BASELINE_CONFIG" ]] || die "baseline config not found: $BASELINE_CONFIG"
[[ -f "$FRAGMENT_CONFIG" ]] || die "fragment config not found: $FRAGMENT_CONFIG"

require_command curl tar make sha256sum

mkdir -p "$CACHE_DIR" "$BUILD_DIR" "$OUT_DIR"

if [[ ! -f "$KERNEL_TARBALL" ]]; then
  tmp_tarball="$KERNEL_TARBALL.tmp"
  rm -f "$tmp_tarball"
  printf 'downloading %s\n' "$KERNEL_TARBALL_URL"
  curl --fail --location --retry 5 --retry-delay 2 --output "$tmp_tarball" "$KERNEL_TARBALL_URL"
  mv "$tmp_tarball" "$KERNEL_TARBALL"
fi

if [[ ! -d "$SRC_DIR" ]]; then
  tmp_extract_dir=$(mktemp -d "$CACHE_DIR/.extract.XXXXXX")
  trap 'rm -rf "$tmp_extract_dir"' EXIT
  printf 'extracting %s\n' "$KERNEL_TARBALL"
  tar -C "$tmp_extract_dir" -xf "$KERNEL_TARBALL"
  mv "$tmp_extract_dir/linux-$KERNEL_VERSION" "$SRC_DIR"
  rm -rf "$tmp_extract_dir"
  trap - EXIT
fi

printf 'merging kernel config\n'
"$SRC_DIR/scripts/kconfig/merge_config.sh" -m -O "$BUILD_DIR" "$BASELINE_CONFIG" "$FRAGMENT_CONFIG"
make -C "$SRC_DIR" O="$BUILD_DIR" ARCH="$ARCH" olddefconfig

while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  symbol=${line%%=*}
  actual=$(grep -E "^${symbol}=" "$BUILD_DIR/.config" || true)
  [[ "$actual" == "$line" ]] || die "config merge did not keep $line (got: ${actual:-unset})"
done < "$FRAGMENT_CONFIG"

if [[ "$CONFIG_ONLY" == false ]]; then
  printf 'building vmlinux with %s jobs\n' "$JOBS"
  make -C "$SRC_DIR" O="$BUILD_DIR" ARCH="$ARCH" -j"$JOBS" vmlinux
fi

config_path="$OUT_DIR/$ARTIFACT_BASENAME.config"
artifact_path="$OUT_DIR/$ARTIFACT_BASENAME"
sha_path="$OUT_DIR/$ARTIFACT_BASENAME.sha256"

install -m 0644 "$BUILD_DIR/.config" "$config_path"

if [[ "$CONFIG_ONLY" == false ]]; then
  install -m 0755 "$BUILD_DIR/vmlinux" "$artifact_path"
  (
    cd "$OUT_DIR"
    sha256sum "$ARTIFACT_BASENAME" > "$ARTIFACT_BASENAME.sha256"
  )
fi

printf '\noutputs:\n'
printf '  config:  %s\n' "$config_path"
if [[ "$CONFIG_ONLY" == false ]]; then
  printf '  kernel:  %s\n' "$artifact_path"
  printf '  sha256:  %s\n' "$sha_path"
else
  printf '  kernel:  skipped (--config-only)\n'
fi
