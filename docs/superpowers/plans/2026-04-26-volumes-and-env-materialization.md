# Volumes And Env Materialization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add extra VM volumes plus host-resolved environment materialization, transported through a read-only metadata drive and consumed by the guest agent.

**Architecture:** Extend config with structured `env` and `volumes`, resolve env on the host, prepare per-volume ext4 images and a metadata image, attach them through the hypervisor abstraction, and teach the guest agent to mount the metadata and extra volumes before launching the workload. Keep proxy env injection and privilege dropping at the final process boundary.

**Tech Stack:** Go, YAML config loading, Firecracker drive attachments through the hypervisor abstraction, ext4 image preparation, guest mount/bind-mount logic, Go unit tests.

---

### Task 1: Extend Config For Structured Env And Volumes

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader.go`
- Test: `internal/config/loader_test.go`

- [ ] Add `EnvConfig`, `EnvCommandConfig`, and `VolumeConfig`.
- [ ] Support `env.static`, `env.from_host`, and `env.from_command`.
- [ ] Validate command-vs-shell exclusivity and volume constraints.
- [ ] Add parsing and validation tests for the new config.

### Task 2: Add Shared Boot Manifest Types And Host Env Resolution

**Files:**
- Create: `pkg/bootmanifest/manifest.go`
- Create: `internal/runtimeenv/resolve.go`
- Test: `internal/runtimeenv/resolve_test.go`

- [ ] Define shared JSON manifest types for command, cwd, env, process, and attached volumes.
- [ ] Implement host-side env resolution for static, host, and command-backed values.
- [ ] Add tests for missing host vars, command failure, newline trimming, and newline rejection.

### Task 3: Add Volume And Metadata Image Preparation

**Files:**
- Create: `internal/volume/prepare.go`
- Create: `internal/volume/sync.go`
- Create: `internal/volume/prepare_test.go`
- Create: `internal/volume/sync_test.go`
- Create: `internal/bootmanifest/image.go`
- Create: `internal/bootmanifest/image_test.go`

- [ ] Prepare directory and file-backed volume images.
- [ ] Implement volume sync-back for directory and file sources.
- [ ] Add metadata image creation for `boot.json`.
- [ ] Add focused tests for both volume kinds and metadata image generation.

### Task 4: Thread Runtime Assets Through Host Runner And VM

**Files:**
- Modify: `internal/cli/host_runner.go`
- Test: `internal/cli/host_runner_test.go`
- Modify: `internal/vm/machine.go`
- Test: `internal/vm/machine_test.go`

- [ ] Materialize env during runtime config preparation.
- [ ] Prepare volume images and metadata image in the runtime dir.
- [ ] Add runtime asset structs for metadata and attached volumes.
- [ ] Attach workspace, metadata, and volume drives in deterministic order.
- [ ] Add tests for env materialization, metadata creation, drive ordering, and volume sync-back orchestration.

### Task 5: Teach The Guest Agent To Read Metadata And Mount Volumes

**Files:**
- Modify: `guest/go.mod`
- Create: `guest/internal/bootmanifest.go`
- Modify: `guest/internal/agent/agent.go`
- Test: `guest/internal/agent/agent_test.go`
- Modify: `guest/internal/init.go`
- Modify: `guest/internal/pty.go`

- [ ] Read the metadata drive from a small bootstrap kernel arg.
- [ ] Parse `boot.json` and merge it with existing cmdline-based boot data during the transition.
- [ ] Mount directory volumes directly and file volumes via bind-mount from a private staging mount.
- [ ] Pass manifest env to the workload path and keep proxy env injection authoritative.
- [ ] Add guest tests for manifest loading, env propagation, and volume mount metadata handling.

### Task 6: Verify And Commit

**Files:**
- Modify: `README.md`
- Modify: `keel.yaml.example`

- [ ] Update usage docs and example config for `env` and `volumes`.
- [ ] Run `go test ./...`.
- [ ] Run `cd guest && go test ./...`.
- [ ] Commit and push the finished feature.
