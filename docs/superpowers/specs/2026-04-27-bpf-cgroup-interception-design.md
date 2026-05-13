# BPF Cgroup Interception Design

## Goal

Replace the current guest-side transparent TCP interception dependency on nftables `REDIRECT` with a cgroup eBPF-based interception path that works on the stock Firecracker 6.1 guest kernel shipped through Keel's default kernel download flow.

The design must preserve the existing guest proxy + host policy architecture:

- guest workloads open outbound TCP connections
- guest proxy receives transparently intercepted connections
- guest proxy forwards the original destination to the host over vsock
- host TCP/DNS/TLS/HTTP policy remains the enforcement point

## Why

The current transparent path depends on guest nftables NAT redirect support and `SO_ORIGINAL_DST`. The stock Firecracker guest kernel available through Keel does not provide the netfilter setup needed for that path by default, so Keel falls back to "proxy-aware clients only".

Runtime probing against the stock guest kernel showed:

- `tc`/`clsact` is unavailable
- cgroup v2 is mounted
- `CONFIG_CGROUP_BPF=y`
- `cgroup/connect4` programs can compile, load, attach, and detach successfully

That makes cgroup socket-address interception the viable stock-kernel path.

## Non-goals

- Replacing host-side policy enforcement
- Implementing a `tc`-based interception path
- Requiring BTF or CO-RE in the guest kernel
- Solving every protocol family in the first iteration

## Design summary

Use guest cgroup eBPF programs to rewrite outbound workload TCP connects to the local guest proxy and use a socket lifecycle handoff path to transfer original destination metadata to the proxy's accepted socket.

Three components are required:

1. **Workload cgroup split**
2. **eBPF program set**
3. **Guest proxy metadata lookup**

## Process and cgroup layout

Create a dedicated cgroup v2 subtree in the guest:

- `/sys/fs/cgroup/keel`
- `/sys/fs/cgroup/keel/workload`
- `/sys/fs/cgroup/keel/proxy`

Placement:

- guest proxy process joins `keel/proxy`
- workload command joins `keel/workload`
- helper/bootstrap process may remain in the root cgroup or a neutral Keel cgroup

This prevents the proxy's own outbound traffic from being rewritten back into itself.

## eBPF program set

### 1. `cgroup/connect4`

Attach to `keel/workload`.

Responsibilities:

- observe workload outbound IPv4 TCP `connect()`
- skip loopback and already-rewritten proxy destinations
- store original destination metadata on the client socket
- rewrite destination to `127.0.0.1:3128`

Context:

- `SEC("cgroup/connect4")`
- use `struct bpf_sock_addr`

Stored metadata:

- original destination IPv4 address
- original destination port
- address family
- protocol marker

### 2. `cgroup/connect6`

Attach to `keel/workload`.

Responsibilities mirror `connect4` for IPv6, but can be deferred until after the IPv4 path is stable.

### 3. `sockops`

Attach to both `keel/workload` and `keel/proxy`.

Responsibilities:

- on client socket establishment, publish a short-lived handoff record keyed by the rewritten connection tuple
- on proxy-side accepted socket establishment, find the corresponding handoff record
- copy original destination metadata onto the accepted socket
- delete the handoff record once consumed

This is the key bridge that replaces `SO_ORIGINAL_DST`.

## Map design

### Socket local storage map

Purpose:

- store original destination metadata on a specific socket

Used by:

- `connect4/connect6` to write client-side metadata
- `sockops` to copy metadata onto the proxy-side accepted socket
- guest proxy userspace to read metadata from accepted sockets

Value:

- family
- destination IP
- destination port

### Handoff LRU map

Purpose:

- bridge metadata between the workload's client socket and the proxy's accepted socket

Key:

- 4-tuple or 5-tuple based on the rewritten localhost flow:
  - source address
  - source port
  - destination address
  - destination port
  - family

Value:

- original destination metadata

Properties:

- LRU map
- bounded size
- deleted on successful consumption

## Userspace proxy behavior

On accepted TCP proxy connections:

1. get the accepted connection file descriptor
2. look up socket-local storage metadata via the pinned BPF map
3. if present:
   - treat the connection as transparently intercepted
   - forward the original destination to the host proxy over vsock
4. if absent:
   - fall back to current explicit HTTP proxy parsing path

This preserves support for both:

- transparent interception
- explicit `HTTP_PROXY` / `HTTPS_PROXY` use

## Guest bootstrap changes

### Proxy process separation

Today the guest proxy and PTY-launched workload live in one bootstrap flow.

The new design should:

- start proxy in its own long-running process
- move proxy PID into `keel/proxy`
- start workload process in `keel/workload`

This likely requires refactoring guest init so the proxy is not just a goroutine in the same process as the workload launcher.

### BPF loader

Keel needs a guest-side loader that:

- mounts bpffs at `/sys/fs/bpf` if not present
- creates the cgroup subtree
- loads and pins the BPF programs and maps
- attaches:
  - `connect4` to `keel/workload`
  - `connect6` to `keel/workload` when enabled
  - `sockops` to both `keel/workload` and `keel/proxy`
- tears down cleanly on exit

Implementation can use libbpf from userspace or direct `bpftool` during prototyping, but the shipped path should be a native guest component, not shelling out to `bpftool`.

## Fallback order

Startup should choose interception mode in this order:

1. **BPF cgroup transparent mode**
2. **Legacy nftables redirect mode**
3. **Proxy-aware-only mode**

Logging should make the chosen mode explicit.

Example:

- `guest interception mode: bpf-cgroup`
- `guest interception mode: nftables-redirect`
- `guest interception mode: explicit-proxy-only`

## Scope boundaries

### Phase 1

- IPv4 only
- `connect4`
- `sockops`
- proxy metadata lookup
- mode selection and fallback

### Phase 2

- IPv6 support
- better observability and metrics
- stale handoff cleanup verification

## Risks

### Process architecture refactor

The biggest risk is not kernel capability; it is separating proxy and workload into different cgroups while preserving the existing PTY and lifecycle model.

### Tuple matching edge cases

The handoff map depends on matching the rewritten localhost flow observed on both sides. It must be validated under concurrency and reconnect churn.

### Incomplete kernel features across versions

The default 6.1 Firecracker kernel supports the cgroup path in probing, but Keel should still feature-detect at runtime and fail closed into the existing fallback order.

## Verification

Verification should include:

- unit tests for cgroup path selection and map key/value encoding
- guest integration test: compile/load/attach BPF programs in guest
- guest integration test: transparent non-proxy-aware TCP client reaches guest proxy through BPF rewrite
- regression test: explicit proxy mode still works
- regression test: proxy traffic is not recursively intercepted
- regression test: fallback to legacy nftables or proxy-only mode when BPF attach fails

