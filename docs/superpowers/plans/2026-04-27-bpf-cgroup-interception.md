# BPF Cgroup Interception Plan

**Goal:** Add a stock-kernel transparent interception path based on cgroup eBPF socket hooks, with guest proxy integration and fallback to existing modes.

## Preconditions

- Use the design in `docs/superpowers/specs/2026-04-27-bpf-cgroup-interception-design.md`
- Preserve host policy semantics and proxy protocol
- Keep nftables redirect as fallback during rollout

## Workstreams

### 1. Guest process and cgroup split

- [ ] Refactor guest bootstrap so the proxy can run in its own process
- [ ] Create `/sys/fs/cgroup/keel/{proxy,workload}`
- [ ] Add helpers to move processes into the correct cgroups
- [ ] Keep PTY behavior unchanged for the user-facing workload

### 2. BPF assets and loader

- [ ] Add guest BPF program sources for:
  - `cgroup/connect4`
  - `sockops`
- [ ] Add build rules to compile guest BPF objects
- [ ] Add a guest-side loader for:
  - bpffs mount
  - map/program pinning
  - cgroup attachment
  - cleanup
- [ ] Feature-detect support before enabling BPF mode

### 3. Metadata handoff path

- [ ] Define socket-local storage value structure
- [ ] Define handoff LRU map key/value structures
- [ ] Implement client-socket metadata write in `connect4`
- [ ] Implement accepted-socket metadata handoff in `sockops`
- [ ] Add userspace helpers for reading original destination metadata from accepted sockets

### 4. Guest proxy integration

- [ ] Update proxy accept path to try BPF metadata first
- [ ] Fall back to explicit HTTP proxy parsing when metadata is missing
- [ ] Preserve current vsock forwarding format to the host proxy

### 5. Interception mode selection and fallback

- [ ] Add mode selection:
  - BPF cgroup
  - nftables redirect
  - explicit proxy only
- [ ] Update warnings and logs to report the active mode clearly
- [ ] Preserve current behavior when neither transparent mode is available

### 6. Tooling and image support

- [ ] Keep BPF probe/build packages in the devtools image:
  - `bpftool`
  - `clang`
  - `llvm`
  - `libbpf-dev`
  - `linux-libc-dev`
- [ ] Ensure CI builds the devtools image with those packages

## Test plan

- [ ] Unit tests for cgroup manager helpers
- [ ] Unit tests for BPF metadata encoding/decoding
- [ ] Guest integration test for loader success on supported kernel
- [ ] Guest integration test for transparent interception of a non-proxy-aware client
- [ ] Guest integration test for fallback to explicit proxy mode
- [ ] Regression test that proxy traffic is not self-intercepted
- [ ] Regression test that explicit proxy clients still work

## Sequencing

Recommended order:

1. process/cgroup split
2. BPF loader skeleton
3. `connect4` program
4. `sockops` handoff
5. proxy metadata lookup
6. fallback/logging
7. tests and CI/image updates

## Risks to watch

- proxy/workload process split may require more guest init refactoring than expected
- handoff map matching must be validated under concurrent connections
- attaching BPF to the wrong cgroup can create recursive proxy loops
- absence of BTF means programs should stay simple and avoid CO-RE assumptions
