# keel

Keel is what you use when “run this coding agent in a VM” is not enough. It gives you a Firecracker microVM, a synced workspace, and a host-enforced egress path that is explicit enough to reason about and strict enough to audit. If you want agent workloads to feel local while still having a real network boundary, policy engine, and shutdown report, this is the tool.

## What Keel is for

Keel runs a command inside a Firecracker VM, mounts your project into that VM as an ext4 workspace image, and syncs changes back to the host when the command exits. The guest runtime is small and purpose-built: it boots a guest agent, brings up the workspace, starts the policy proxies, and then hands control to the requested command.

Use it when you want:

- a disposable VM boundary around an agent or build task
- a writable project workspace inside the VM
- controlled egress for package managers, CLIs, curl, SDKs, and Docker-in-VM
- a post-run network summary
- an audit mode that shows what policy would have blocked without actually blocking it

## Installation

Keel currently targets Linux hosts for real execution.

Host requirements:

- KVM available at `/dev/kvm`
- `firecracker` in `PATH`
- `sudo`
- `mkfs.ext4`
- `debugfs`
- `iptables`
- `ip6tables`

Keel also needs the guest agent artifact at `dist/keel-agent` relative to the `keel` binary. If that file is missing, image pull and run commands will fail with a targeted error telling you which paths were checked.

Operational requirements:

- the user running `keel` must be able to open `/dev/kvm`
- the host must allow creation of TAP devices
- the host must allow the `iptables` and `ip6tables` rules Keel installs for the VM TAP

macOS currently has only a stub hypervisor backend. The abstraction layer is in place, but VM execution is Linux-only today.

## Quickstart

Initialize a project config:

```bash
keel config init
```

Show the resolved config after defaults, global config, and project config are merged:

```bash
keel config show
```

Run a shell in the default VM image:

```bash
keel -- /bin/sh
```

On interactive terminals, Keel shows a compact startup indicator while it resolves the image, prepares the workspace and volumes, writes boot metadata, and starts the VM. The loader clears itself before guest output attaches, so the shell or command output still starts cleanly.

Run a single command:

```bash
keel -- /bin/sh -lc 'go test ./...'
```

Pre-pull and cache an image:

```bash
keel image pull ubuntu:24.04
```

List cached images:

```bash
keel image list
```

Remove a cached image:

```bash
keel image rm ubuntu:24.04
```

## Common use cases

### Run an agent in a VM with a synced workspace

```bash
keel -- /bin/sh -lc 'pwd && ls -la && git status --short'
```

Expected behavior:

- the command runs inside the VM
- the project is mounted at `/workspace` by default
- stdout and stderr stream back to the host
- a network summary is printed on shutdown if there was network activity

### Run a one-off tool with egress policy

```bash
keel -- curl -fsS https://api.github.com/repos/moolen/keel
```

Useful when you want the command to have network access only through the Keel policy path.

### Build with Docker inside the VM

```yaml
features:
  - name: docker
    config:
      storage_driver: vfs
```

Then:

```bash
keel -- docker build --no-cache .
```

Keel starts `dockerd` inside the guest, configures it for proxy-based egress, and keeps the host TAP interface default-deny.

### Choose the guest kernel

Keel now defaults to a release-managed guest kernel:

```yaml
kernel:
  source: release://latest
```

Supported forms:

```yaml
kernel:
  source: release://v0.2.0
```

```yaml
kernel:
  source: https://example.com/vmlinux
```

```yaml
kernel:
  path: /opt/keel/vmlinux
```

The release-managed kernel is the default path for Keel runs and is intended to
include the netfilter and Docker-friendly guest networking features Keel
expects. If you want to build your own local variant, use:

```bash
./hack/kernel/build-kernel.sh
```

Then point Keel at the built file with `kernel.path`.

### Observe policy without enforcing it

```yaml
network:
  audit: true
  dns:
    denied:
      - "*.example.com"
```

Then:

```bash
keel -- curl -fsS https://api.example.com/data
```

The request is allowed, but the shutdown summary reports `policy=would_deny`.

## CLI examples

Override the configured image for one run:

```bash
keel --image curlimages/curl:latest -- curl -fsS https://httpbin.org/get
```

See what Keel would do without booting a VM:

```bash
keel --dry-run -- /bin/sh -lc 'echo hello'
```

Verbose host-side execution:

```bash
keel -v -- /bin/sh -lc 'echo hello'
```

## Full `keel.yaml`

This is a full example config with inline explanations. It is intentionally verbose and meant as a reference document, not a minimal starter file.

```yaml
# OCI image used as the guest root filesystem.
image: ubuntu:24.04

# Optional override for where cached OCI/rootfs artifacts live.
image_cache_dir: ~/.cache/keel/images

# Kernel selection. Use `path` for a host-managed kernel image, or `source`
# for a release-managed or remote kernel source.
kernel:
  source: release://latest

  # Supported forms:
  # path: /opt/keel/vmlinux
  # source: release://latest
  # source: release://v0.2.0
  # source: https://example.com/vmlinux

resources:
  # Number of guest vCPUs.
  vcpu: 2

  # Guest memory size in MiB.
  memory_mb: 2048

  # Workspace image size in MiB.
  disk_mb: 4096

workspace:
  # Host path copied into the VM workspace image before boot.
  mount: .

  # Mountpoint inside the guest.
  target: /workspace

  # Copy VM changes back to the host after exit.
  sync_back: true

  # Allow deletions made inside the VM to be applied to the host.
  sync_deletes: false

  # Ask for confirmation before applying sync-back changes.
  sync_confirm: true

volumes:
  # Extra host file or directory paths attached as separate block devices.
  - source: ./.cache/pip

    # Absolute guest target path. Directories mount directly; files bind-mount.
    target: /cache/pip

    # Mount read-only inside the guest.
    read_only: false

    # Copy changes back to the host source on exit for writable volumes.
    sync_back: false

    # Leave host-created ownership as-is, or chown the mounted target root
    # to the configured process uid/gid before exec.
    ownership: process

network:
  # Transport mode for host/guest service wiring.
  # Current real implementation uses vsock-backed host services.
  mode: vsock

  # Audit mode keeps policy evaluation active but converts denies into runtime allows.
  # Shutdown summaries report those results as policy=would_deny.
  audit: false

  # Require TLS SNI on port 443 when DNS correlation is used.
  deny_if_no_sni: true

  dns:
    # Domain allowlist applied to DNS questions.
    allowed:
      - api.github.com
      - auth.docker.io
      - registry-1.docker.io
      - "*.docker.io"
      - "*.github.com"

    # Domain denylist applied before the allowlist.
    denied:
      - gist.github.com

  tcp:
    # Coarse IP allowlist fallback for destinations that are not DNS-correlated.
    allowed_cidrs: []

    # Coarse IP denylist applied before allowlist/correlation.
    denied_cidrs:
      - 10.0.0.0/8

  tls:
    # SNI allowlist for TLS traffic on port 443.
    allowed_sni:
      - api.github.com
      - auth.docker.io
      - registry-1.docker.io
      - "*.github.com"

    # SNI denylist checked before allowed_sni.
    denied_sni:
      - gist.github.com

  mitm:
    # Enable HTTP-aware policy over HTTPS by terminating TLS with a local CA.
    enabled: false

    # Current behavior is optional inspection, not a second transport mode.
    mode: optional

    # What to do when upstream TLS trust cannot be established.
    on_untrusted_cert: deny

    # Record HTTP request activity through the MITM path.
    log_requests: true

    ca:
      # Name used for the persisted local CA.
      name: keel-local-ca

      # Install the CA into the guest trust store.
      install_system: true

      # Install the CA into Docker daemon/client trust paths in the guest.
      install_docker: true

    bypass:
      # Hosts that should not go through HTTP MITM inspection.
      hosts: []

      # SNI patterns that should bypass MITM on TLS flows.
      sni: []

  http:
    # Default HTTP policy result after MITM inspection.
    default: deny

    # Ordered first-match HTTP policy rules.
    rules:
      - action: allow
        host: api.github.com
        methods: ["GET"]
        paths:
          - /repos/*
          - /users/*

      - action: deny
        host: "*.github.com"
        methods: ["POST", "PUT", "PATCH", "DELETE"]
        paths:
          - /*

features:
  - name: docker
    config:
      # Current supported practical choice.
      storage_driver: vfs

      # Optional registry mirror list passed to dockerd.
      registry_mirrors: []

process:
  # Optional credential drop for the final workload command.
  uid: 1000
  gid: 1000
  supplementary_gids: [27]

env:
  static:
    TERM: xterm-256color
    PIP_CACHE_DIR: /cache/pip

  from_host:
    # guest env name: host env name
    GITHUB_TOKEN: GITHUB_TOKEN

  from_command:
    # command-backed values are resolved on the host before boot.
    BUILD_SHA:
      command: ["git", "rev-parse", "HEAD"]
    OP_SESSION:
      shell: "op read op://dev/session/token"
```

## How config resolution works

Keel resolves configuration in this order:

1. built-in defaults
2. global config at `~/.config/keel/config.yaml`
3. nearest project `keel.yaml`
4. CLI overrides such as `--image`

Useful command:

```bash
keel config show
```

That prints the final resolved config exactly as the runtime sees it.

## Network path

This is the most important part of Keel.

Keel does not just “give the VM networking.” It builds a controlled path from guest workloads to host policy services and tries hard to keep everything else closed.

### High-level flow

1. Keel creates a TAP-backed NIC for the VM.
2. The host assigns a tiny point-to-point subnet to that TAP.
3. The host installs default-deny `iptables` and `ip6tables` rules for the TAP interface.
4. The guest uses host-backed DNS and TCP policy services over vsock.
5. Proxy-aware clients use the guest proxy path explicitly.
6. If the guest kernel supports the required netfilter features, Keel also transparently redirects guest TCP egress into the guest proxy.
7. The host policy engine evaluates DNS, TCP/TLS, and optionally HTTP rules.
8. On shutdown, Keel prints an aggregated summary.

### What is enforced on the host

Host enforcement today is primarily:

- TAP interface default-deny for direct guest traffic
- host DNS proxy policy
- host TCP/TLS proxy policy
- optional host MITM HTTP policy

The critical property is this:

- direct guest TAP egress is blocked at the host boundary
- allowed traffic must go through the Keel proxy path

That means:

- ICMP is blocked
- direct UDP to arbitrary ports is blocked
- direct TCP egress is blocked
- non-proxy-aware clients fail closed when transparent capture is unavailable

### DNS path

Inside the guest:

- `/etc/resolv.conf` is rewritten to `nameserver 127.0.0.1`
- the guest runs a DNS forwarder on `127.0.0.1:53`
- the forwarder sends queries to the host over vsock port `3053`

On the host:

- the DNS proxy evaluates `network.dns.allowed` and `network.dns.denied`
- allowed answers are returned to the guest
- returned IPs are tracked for later TCP correlation

Effectively, DNS is both a gate and an input to later TCP policy.

### TCP and TLS path

Inside the guest:

- commands run with `HTTP_PROXY` and `HTTPS_PROXY` pointing at the guest proxy on `127.0.0.1:3128`
- the guest TCP proxy forwards requests to the host over vsock port `3128`

If transparent redirect is available:

- guest TCP traffic is redirected into the guest proxy automatically
- non-proxy-aware clients can still be captured and evaluated

If transparent redirect is not available:

- direct TAP egress remains blocked on the host
- only proxy-aware clients work
- Keel prints a warning telling you that transparent redirect is unavailable on the default kernel

On the host:

- the TCP proxy evaluates coarse destination policy
- it correlates destination IPs back to previously allowed DNS answers
- for TLS on `:443`, it inspects SNI when available
- it applies `deny_if_no_sni`, `tls.denied_sni`, and `tls.allowed_sni`

### HTTP MITM path

When `network.mitm.enabled: true`:

- the host TCP proxy can terminate TLS for eligible HTTPS flows
- Keel issues leaf certificates from a persisted local CA
- the guest trust store can be updated with that CA
- Docker daemon/client trust can also be updated in the guest

Once the request is visible as HTTP:

- Keel applies ordered `network.http.rules`
- matching fields are `host`, `method`, and `path`
- `path` uses glob-style matching
- if no rule matches, `network.http.default` is applied

This is how Keel turns “allow GitHub” into “allow only `GET /repos/*` on `api.github.com`”.

### Audit mode

When `network.audit: true`:

- policy evaluation still happens
- requests are allowed through the proxy path
- deny results are recorded as `would_deny`

Example summary:

```text
Network summary:
dns  example.com:53 policy=would_deny count=4
tcp  api.github.com:443 policy=allowed count=2
http api.github.com POST /repos/123 policy=would_deny count=1
```

Audit mode is useful for tightening policies without immediately breaking workloads.

## What the network model supports

Supported today:

- DNS allow/deny policy
- TCP/IP CIDR allow/deny policy
- TLS SNI allow/deny policy
- `deny_if_no_sni`
- HTTP `host + method + path` policy through MITM
- audit mode
- aggregated shutdown summaries
- Docker-in-VM through the proxy path
- proxy-only Docker build and `docker run` egress

Supported operational modes:

- explicit proxy clients
- transparent TCP capture when the guest kernel supports it

## What it does not support well yet

Important limits:

- GitHub-hosted CI cannot run the full Firecracker/KVM e2e suite; those tests need a suitable Linux host
- macOS VM execution is not implemented yet
- arbitrary Docker build-stage trust injection for MITM is still best-effort by base image
- HTTP policy only matches `host`, `method`, and `path` today
- query-string, header, and body-aware policy are not implemented
- HTTP policy depends on MITM being enabled for HTTPS

## Docker behavior

The Docker feature starts `dockerd` inside the guest and configures it for proxy-based egress.

What works:

- `docker pull`
- `docker run`
- `docker build`

What matters operationally:

- your DNS/TLS allowlists must include the real registry and CDN hosts involved in the pull path
- for HTTPS interception, Docker daemon/client trust is supported
- arbitrary build-stage CA trust inside every base image is not guaranteed yet

## Shutdown summary

At VM shutdown, Keel prints an aggregated network report on stderr. It groups traffic by protocol, host, port, and policy decision.

Example:

```text
Network summary:
dns  api.github.com:53 policy=allowed count=2
dns  example.com:53 policy=would_deny count=3
http api.github.com GET /repos/123 policy=allowed count=1
tcp  api.github.com:443 policy=allowed count=1
```

That report is the fastest way to see what the workload actually tried to do and what the configured policy thought about it.
