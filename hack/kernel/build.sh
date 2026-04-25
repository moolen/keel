#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LINUX_VERSION=${LINUX_VERSION:-6.12.25}
ARCH=${ARCH:-x86_64}
JOBS=${JOBS:-$(nproc)}
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/hack/kernel/out"}
SRC_DIR=${SRC_DIR:-"$OUT_DIR/linux-$LINUX_VERSION"}
CONFIG_FRAGMENT=${CONFIG_FRAGMENT:-"$ROOT_DIR/hack/kernel/config"}

mkdir -p "$OUT_DIR"

if [[ ! -d "$SRC_DIR" ]]; then
  archive="$OUT_DIR/linux-$LINUX_VERSION.tar.xz"
  curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz" -o "$archive"
  tar -C "$OUT_DIR" -xf "$archive"
fi

cd "$SRC_DIR"

if [[ ! -f .config ]]; then
  make x86_64_defconfig
fi

scripts/config --file .config \
  --disable MODULES \
  --enable DEVTMPFS \
  --enable DEVTMPFS_MOUNT \
  --enable VSOCKETS \
  --enable VIRTIO_VSOCKETS \
  --enable VHOST_VSOCK \
  --enable VIRTIO_BLK \
  --enable VIRTIO_MMIO \
  --enable EXT4_FS \
  --enable OVERLAY_FS \
  --enable CGROUPS \
  --enable CGROUP_BPF \
  --enable NETFILTER \
  --enable NETFILTER_NETLINK \
  --enable NF_TABLES \
  --enable NF_TABLES_INET \
  --enable NF_TABLES_IPV4 \
  --enable NF_TABLES_IPV6 \
  --enable NF_NAT \
  --enable NFT_NAT \
  --enable NFT_REDIR \
  --enable NFT_CHAIN_NAT \
  --enable IP_NF_IPTABLES \
  --enable IP_NF_NAT \
  --enable IPV6 \
  --enable SERIAL_8250 \
  --enable SERIAL_8250_CONSOLE

if [[ -f "$CONFIG_FRAGMENT" ]]; then
  while read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    case "$line" in
      *=y)
        scripts/config --file .config --enable "${line%%=*}"
        ;;
      *=n)
        scripts/config --file .config --disable "${line%%=*}"
        ;;
    esac
  done < "$CONFIG_FRAGMENT"
fi

make olddefconfig < /dev/null
make -j"$JOBS" vmlinux

cp .config "$OUT_DIR/config"
cp vmlinux "$OUT_DIR/vmlinux"

cat <<EOF
kernel build complete
  source:  $SRC_DIR
  config:  $OUT_DIR/config
  vmlinux: $OUT_DIR/vmlinux

Use this kernel with:
  keel --verbose -- /bin/sh

or set:
  kernel:
    path: $OUT_DIR/vmlinux
EOF
