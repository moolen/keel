# Keel — Implementation Plan

**Firecracker-based VM sandbox for AI coding agents**

Keel wraps commands in an ephemeral Firecracker microVM with transparent network policy enforcement via vsock. It provides full PTY interactivity, Docker-in-VM support, and safe workspace synchronization — stronger isolation than namespace-based sandboxes like Fence, while maintaining the same ergonomics.

```
keel -- claude code
keel -- opencode
keel -- curl https://example.com
keel image pull ubuntu:24.04
```

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│  keel CLI (Host)                                         │
│                                                          │
│  ┌────────────────┐  ┌─────────────────────────────────┐ │
│  │ VM Lifecycle    │  │ vsock Services                  │ │
│  │                 │  │                                 │ │
│  │ • OCI → rootfs  │  │  :1000  PTY control plane      │ │
│  │ • workspace img │  │  :3128  transparent TCP proxy   │ │
│  │ • firecracker   │  │  :3053  DNS policy proxy        │ │
│  │   go-sdk        │  │                                 │ │
│  └────────┬────────┘  │  Policy Engine                  │ │
│           │           │  • DNS allowlist + response     │ │
│           │           │    tracking (domain → IP map)   │ │
│           │           │  • TCP allow by correlated      │ │
│           │           │    domain or CIDR allowlist      │ │
│           │           │  • TLS SNI validation           │ │
│           │           │  • deny-if-no-sni mode          │ │
│           │           └──────────┬──────────────────────┘ │
│           │                      │                        │
│      vsock UDS                   │                        │
│           │                      │                        │
└───────────┼──────────────────────┼────────────────────────┘
            │       AF_VSOCK       │
┌───────────┴──────────────────────┴────────────────────────┐
│  Firecracker microVM  (NO network interfaces)             │
│                                                           │
│  /dev/vda  ← rootfs (OCI image + keel guest agent layer)  │
│  /dev/vdb  ← workspace (copy of host directory)           │
│                                                           │
│  keel-agent (PID 1 or early init)                         │
│   ├── PTY handler (vsock :1000)                           │
│   ├── transparent proxy (vsock :3128, :3053)              │
│   └── iptables rules (redirect all AF_INET)               │
│                                                           │
│  [optional] dockerd (if docker feature enabled)           │
└───────────────────────────────────────────────────────────┘
```

---

## 2. Project Structure

```
keel/
├── cmd/
│   └── keel/
│       └── main.go                 # CLI entrypoint (cobra)
├── internal/
│   ├── cli/                        # CLI command definitions
│   │   ├── root.go                 # root command, config loading
│   │   ├── run.go                  # `keel -- <cmd>` logic
│   │   ├── image.go                # `keel image pull/list/rm`
│   │   └── config.go               # `keel config show/init`
│   ├── config/
│   │   ├── config.go               # config types + merging
│   │   ├── loader.go               # YAML loading, hierarchy
│   │   └── defaults.go             # default values
│   ├── vm/
│   │   ├── machine.go              # firecracker VM lifecycle
│   │   ├── kernel.go               # kernel management
│   │   └── drives.go               # rootfs + workspace drive creation
│   ├── image/
│   │   ├── pull.go                 # OCI pull (go-containerregistry)
│   │   ├── convert.go              # OCI → ext4 rootfs
│   │   ├── cache.go                # local image cache management
│   │   └── inject.go               # layer keel guest agent into rootfs
│   ├── network/
│   │   ├── policy.go               # policy engine (DNS + TCP + SNI)
│   │   ├── dns.go                  # host-side DNS proxy over vsock
│   │   ├── tcp.go                  # host-side TCP proxy over vsock
│   │   ├── sni.go                  # TLS ClientHello SNI parser
│   │   └── tracker.go              # DNS response → IP correlation cache
│   ├── vsock/
│   │   ├── host.go                 # host-side vsock listener (UDS)
│   │   └── protocol.go             # framing protocol definitions
│   ├── pty/
│   │   ├── host.go                 # host-side PTY over vsock
│   │   └── resize.go               # terminal resize propagation
│   ├── workspace/
│   │   ├── prepare.go              # host dir → ext4 image
│   │   ├── sync.go                 # post-exit diff + sync-back
│   │   └── diff.go                 # file-level diffing
│   └── features/
│       ├── registry.go             # feature registry
│       └── docker.go               # docker feature (init, config)
├── guest/                          # guest-side agent (compiled separately)
│   ├── cmd/
│   │   └── keel-agent/
│   │       └── main.go             # guest agent entrypoint
│   ├── internal/
│   │   ├── init.go                 # init sequence (mount, iptables, etc.)
│   │   ├── pty.go                  # PTY server over vsock
│   │   ├── proxy.go                # transparent TCP proxy (SO_ORIGINAL_DST)
│   │   ├── dns.go                  # DNS UDP→vsock forwarder
│   │   └── features/
│   │       └── docker.go           # start/configure dockerd
│   └── go.mod                      # separate module (minimal deps)
├── hack/
│   ├── kernel/
│   │   ├── config                  # kernel .config for firecracker
│   │   └── build.sh                # kernel build script
│   └── test/
│       ├── integration_test.go     # end-to-end VM tests
│       └── policy_test.go          # network policy unit tests
├── keel.yaml.example               # example project config
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## 3. Configuration

### 3.1 Config Hierarchy (lowest → highest priority)

1. Built-in defaults
2. Global config: `~/.config/keel/config.yaml`
3. Project config: `./keel.yaml` (walk up to find it)
4. CLI flags

### 3.2 Config Schema

```yaml
# keel.yaml — project-level config
image: ubuntu:24.04

kernel: # optional, override default
  path: /path/to/custom/vmlinux

resources:
  vcpu: 2
  memory_mb: 2048
  disk_mb: 4096

workspace:
  mount: .                # host directory to mount (default: cwd)
  target: /workspace      # mount point inside VM
  sync_back: false        # sync changes back to host on exit
  sync_deletes: false     # propagate file deletions on sync
  sync_confirm: true      # show diff and ask before syncing

network:
  mode: vsock             # only vsock for now, extensible later
  deny_if_no_sni: false   # reject TLS connections without SNI
  dns:
    allowed:
      - "*.github.com"
      - "registry.npmjs.org"
      - "pypi.org"
      - "*.docker.io"
    denied: []            # explicit deny (takes precedence)
  tcp:
    allowed_cidrs:        # fallback for IP-direct connections
      - "0.0.0.0/0"       # (default: deny all not resolved via DNS)
    denied_cidrs: []
  tls:
    allowed_sni:          # additional SNI-based rules
      - "*.github.com"
    denied_sni: []

features:
  - name: docker
    config:
      storage_driver: overlay2
      registry_mirrors: []

env:                      # environment variables set inside VM
  TERM: xterm-256color
```

### 3.3 Global Config

```yaml
# ~/.config/keel/config.yaml
image_cache_dir: ~/.cache/keel/images
kernel_path: ~/.cache/keel/kernel/vmlinux   # auto-downloaded on first run
default_resources:
  vcpu: 2
  memory_mb: 2048
  disk_mb: 4096
```

---

## 4. Implementation Phases

### Phase 1 — Foundation (VM lifecycle + PTY)

**Goal:** `keel -- /bin/sh` boots a VM and drops you into an interactive shell.

#### 1.1 CLI Scaffold
- Set up cobra CLI with `run` (implicit, everything after `--`), `image`, `config` subcommands
- Implement config loading with hierarchy merging
- Wire up signal handling (SIGINT, SIGTERM → graceful VM shutdown)

#### 1.2 OCI Image Management
- Use `go-containerregistry` (github.com/google/go-containerregistry) to pull images
- Use Docker's credential helpers for auth (read `~/.docker/config.json` — same source as `docker pull`)
- Cache pulled images as flattened tarballs in `~/.cache/keel/images/<registry>/<repo>/<tag>/`
- Convert to ext4 rootfs: unpack tarball → create + populate ext4 image via `mkfs.ext4` + loop mount

#### 1.3 Guest Agent Injection
- Compile `keel-agent` as a static binary (CGO_ENABLED=0, linux/amd64)
- After creating the ext4 rootfs from OCI, mount it and inject:
  - `/usr/local/bin/keel-agent` (the static binary)
  - `/etc/keel/init.sh` (init script that launches the agent)
- Modify `/sbin/init` or set kernel `init=` boot param to point to keel-agent

#### 1.4 Kernel Management
- Bundle a default kernel or download on first run to `~/.cache/keel/kernel/vmlinux`
- Kernel config must include: `CONFIG_VIRTIO_VSOCK`, `CONFIG_VHOST_VSOCK`, overlay fs, cgroups v2, netfilter (for guest iptables), devtmpfs
- Provide `hack/kernel/config` and `hack/kernel/build.sh` for custom builds

#### 1.5 Firecracker VM Boot
- Use `firecracker-go-sdk` to configure and start the VM
- Drives: rootfs (`/dev/vda`, rw) + workspace (`/dev/vdb`, rw)
- vsock device with unique CID per instance
- No network interfaces
- Wait for guest agent to signal readiness over vsock (port 1000)

#### 1.6 PTY Over vsock
- **Host side:** put local terminal into raw mode, forward stdin/stdout over vsock port 1000. Send terminal resize events (SIGWINCH) as out-of-band messages.
- **Guest side:** keel-agent allocates a PTY (`pty.Open()`), spawns the user's command in it, and bridges the PTY fd to vsock port 1000.
- **Framing protocol on port 1000:**
  - `0x01 <len:u32> <data>` — stdin/stdout data
  - `0x02 <rows:u16> <cols:u16>` — resize
  - `0x03 <code:u8>` — exit code
  - `0x04 <signal:u8>` — signal forwarding (ctrl+c → SIGINT)

#### 1.7 Workspace Drive
- Create ext4 image from host directory contents (copy via loop mount)
- Guest agent mounts `/dev/vdb` at `/workspace` (or configured target)
- User's command runs with cwd set to `/workspace`

**Phase 1 deliverable:** You can run `keel -- /bin/sh` and get a fully interactive shell inside a Firecracker VM. No networking, no Docker, no policies yet.

---

### Phase 2 — Network Policy Engine

**Goal:** Transparent network policy enforcement. DNS + TCP + TLS/SNI filtering, all over vsock.

#### 2.1 Guest-Side Transparent Proxy
- keel-agent sets up iptables rules during init:
  ```
  iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <agent-uid> -j RETURN
  iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 3128
  iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 3053
  ```
- TCP transparent proxy:
  - Listen on `0.0.0.0:3128`
  - Recover original destination via `SO_ORIGINAL_DST` (getsockopt)
  - Send destination header over vsock to host (CID 2, port 3128)
  - Bridge bidirectionally
- DNS forwarder:
  - Listen UDP on `0.0.0.0:3053`
  - Forward DNS queries over vsock (CID 2, port 3053) with length-prefix framing
  - Return responses to original caller

#### 2.2 Host-Side DNS Policy Proxy
- Listen on vsock UDS port 3053
- Parse DNS query to extract question name
- Policy check: match against `network.dns.allowed` / `network.dns.denied` (glob matching, denied takes precedence)
- If allowed: forward to system resolver, parse response, extract A/AAAA records
- **Track resolved IPs**: maintain a TTL-aware map of `domain → []IP` for TCP correlation
- If denied: return NXDOMAIN or REFUSED
- Log all decisions

#### 2.3 Host-Side TCP Policy Proxy
- Listen on vsock UDS port 3128
- Read destination header (IP:port) from guest proxy
- **Correlation lookup**: check if destination IP was resolved via an allowed DNS query
- **CIDR fallback**: if not in DNS cache, check against `network.tcp.allowed_cidrs`
- If denied: close connection (guest sees RST), log
- If allowed: dial upstream, bridge bidirectionally

#### 2.4 TLS SNI Inspection
- For TCP connections to port 443 (or configurable TLS ports):
  - After connecting the upstream, peek at the first bytes from the guest side
  - Parse TLS ClientHello to extract SNI extension
  - Validate SNI against `network.tls.allowed_sni` / `network.tls.denied_sni`
  - If `deny_if_no_sni: true` and no SNI present → block
  - Cross-check: SNI must match the domain that resolved to this IP (prevents SNI spoofing against the DNS correlation)
- Implementation: parse just enough of the TLS record layer + handshake header + extensions to extract SNI. No need for a full TLS library — it's ~100 lines of parsing.

#### 2.5 DNS→TCP Correlation Engine (`tracker.go`)
- Thread-safe map: `IP → {domain, resolvedAt, ttl}`
- Populated by DNS proxy when forwarding successful responses
- Queried by TCP proxy before allowing connections
- Entries expire based on DNS TTL (with a configurable minimum, e.g., 60s)
- Handles multiple domains resolving to same IP (allow if any is permitted)

#### 2.6 Policy Logging
- Structured logging (JSON or human-readable based on TTY detection)
- Log levels: allowed (debug), denied (warn), errors (error)
- Include: timestamp, direction (dns/tcp), domain, IP, port, SNI (if present), decision, matched rule

**Phase 2 deliverable:** `keel -- curl https://github.com` works if github.com is in the DNS allowlist. Connections to non-allowed domains are transparently blocked. SNI is validated on TLS connections.

---

### Phase 3 — Features System + Docker

**Goal:** `features:` config enables Docker-in-VM and is extensible for future features.

#### 3.1 Feature Registry
- Features implement a `Feature` interface:
  ```go
  type Feature interface {
      Name() string
      ValidateConfig(raw map[string]any) error
      PrepareRootfs(rootfsPath string, config map[string]any) error  // inject files at build time
      GuestInit(config map[string]any) ([]InitAction, error)         // actions for guest agent
  }
  ```
- Features can modify the rootfs during image preparation and provide init-time actions for the guest agent

#### 3.2 Docker Feature
- **Rootfs preparation:** verify Docker/containerd binaries exist in the image. If not, inject them (or error with a helpful message suggesting a Docker-enabled base image).
- **Guest init actions:**
  - Create required directories (`/var/lib/docker`, etc.)
  - Configure Docker daemon (`/etc/docker/daemon.json` with storage driver, mirrors)
  - Start `dockerd` as a background process
  - Wait for Docker socket to be available before executing user command
- **Proxy propagation:** configure Docker daemon to use the guest's transparent proxy for registry pulls. Since iptables capture is transparent, this should work automatically — but daemon.json can also set explicit proxy config as a fallback.

#### 3.3 Feature Config Passing
- Features receive their config block from `keel.yaml`:
  ```yaml
  features:
    - name: docker
      config:
        storage_driver: overlay2
  ```
- Config is validated at CLI startup before VM boot

**Phase 3 deliverable:** `keel -- docker build .` works inside the VM. Docker pulls go through the policy engine transparently.

---

### Phase 4 — Workspace Sync

**Goal:** Safe, confirmed sync-back of workspace changes to the host.

#### 4.1 Post-Exit Diff
- After VM exits, mount the workspace ext4 image read-only
- Walk both trees (host directory + VM workspace image) and compute diff:
  - Added files (in VM, not on host)
  - Modified files (different content or mtime)
  - Deleted files (on host, not in VM)
- Use content hashing (xxhash or sha256) for reliable modification detection

#### 4.2 Sync Confirmation
- If `sync_confirm: true` (default), print summary and prompt:
  ```
  Workspace changes detected:
    modified:  3 files
    added:     1 file
    deleted:   2 files

  Show details? [y/N/d(iff)]
  ```
- `d` shows a detailed file list (and optionally per-file diffs for text files)
- User confirms before any host modification

#### 4.3 Safe Sync Application
- Apply additions and modifications by copying from mounted workspace image
- Deletions only applied if `sync_deletes: true`
- Atomic where possible: write to `.keel-sync-tmp/` first, then rename
- If sync fails mid-way, leave partial results in tmp dir for manual recovery

**Phase 4 deliverable:** Changes made inside the VM can be safely reviewed and synced back to the host directory.

---

### Phase 5 — Polish + UX

**Goal:** Production-quality CLI experience.

#### 5.1 `keel image` Subcommands
- `keel image pull <ref>` — pull and cache an OCI image, test auth
- `keel image list` — show cached images with sizes
- `keel image rm <ref>` — remove cached image

#### 5.2 `keel config` Subcommands
- `keel config show` — print resolved config (merged hierarchy)
- `keel config init` — generate a starter `keel.yaml` in cwd

#### 5.3 Boot Performance
- Pre-compute and cache the rootfs ext4 for each OCI image (only rebuild on pull)
- Guest agent injection is cached as part of the rootfs (invalidate on keel version change)
- Workspace drive creation is the only per-invocation cost

#### 5.4 Cleanup + Error Handling
- Deferred cleanup: always remove workspace images, vsock UDS files on exit
- Handle SIGINT/SIGTERM: forward signal to guest, wait for exit, clean up
- Timeout: configurable maximum VM lifetime, hard kill after grace period
- Clear error messages for common failures: firecracker not installed, KVM not available, image pull auth failure

#### 5.5 Logging + Diagnostics
- `-v` / `--verbose` flag for debug output
- `--dry-run` to show what would happen without booting a VM
- Network policy decisions logged to stderr (filterable by level)

---

## 5. Key Dependencies

| Dependency | Purpose |
|---|---|
| `firecracker-microvm/firecracker-go-sdk` | VM lifecycle management |
| `google/go-containerregistry` | OCI image pull, unpack, auth |
| `spf13/cobra` | CLI framework |
| `creack/pty` | PTY allocation (guest agent) |
| `miekg/dns` | DNS message parsing (host policy engine) |
| `rs/zerolog` or `slog` | Structured logging |
| `golang.org/x/sys/unix` | vsock (AF_VSOCK), SO_ORIGINAL_DST |

---

## 6. Guest Agent Build

The guest agent (`keel-agent`) is a separate Go module under `guest/` to keep its dependency tree minimal. It's compiled as a fully static binary:

```makefile
guest-agent:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" -o ../dist/keel-agent ./cmd/keel-agent
```

The agent binary is embedded into the host `keel` binary (via `//go:embed`) so there's no external file to manage — `keel` extracts and injects it into the rootfs at image preparation time.

---

## 7. vsock Protocol Summary

| Port | Direction | Purpose | Framing |
|---|---|---|---|
| 1000 | Bidirectional | PTY control plane | Type byte + length-prefixed messages |
| 3128 | Guest → Host | TCP proxy tunnel | 1-byte addr len + addr:port string + raw stream |
| 3053 | Guest → Host | DNS query forwarding | u16 length prefix + raw DNS message |

---

## 8. Security Considerations

- **No network interfaces** in the VM — all AF_INET traffic is captured by iptables and tunneled through the policy engine. There is no IP-level escape path.
- **vsock is the only communication channel** — limited to the three defined ports. The attack surface is the framing protocol parser + policy engine.
- **Workspace is a copy** — host directory is never directly mounted. Sync-back requires explicit opt-in and user confirmation.
- **Guest agent runs as init** — it controls the iptables rules before any user process starts. A user process cannot remove the rules without root inside the VM (and even then, there's no network interface to exploit).
- **SNI validation prevents domain fronting** — even if DNS resolves correctly, the TLS SNI must match an allowed pattern. `deny_if_no_sni` blocks TLS connections that omit SNI entirely.
- **DNS correlation prevents IP-direct bypass** — TCP connections to IPs not seen in DNS responses are denied unless explicitly allowed via CIDR rules.

---

## 9. Future Extensions (Out of Scope for Initial Implementation)

- **TAP-based networking mode** — for use cases that need full IP connectivity (e.g., running a server inside the VM)
- **Snapshot/restore** — cache a booted VM state for faster startup
- **Filesystem policy** — read-only mounts, path-level access control inside the VM
- **Multi-VM orchestration** — run multiple sandboxes in parallel
- **MCP integration** — expose keel as a tool for AI agents to self-sandbox
- **Named/persistent VMs** — `keel start`, `keel exec`, `keel stop` lifecycle
