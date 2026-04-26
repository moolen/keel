# Compact Startup Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a compact 3-5 line startup progress UI for interactive `keel` runs, showing a progress bar, step counter, and short status text during VM preparation.

**Architecture:** Add a tiny Bubble Tea renderer in `internal/cli` and wire explicit startup phase updates through `HostRunner` and the VM launch path. Keep the UI inline, TTY-gated, and removable before PTY attach so guest output stays unchanged.

**Tech Stack:** Go, Bubble Tea, Bubbles progress component, existing host runner startup phases, Go unit tests.

---

### Task 1: Add Progress Renderer

**Files:**
- Create: `internal/cli/progress.go`
- Create: `internal/cli/progress_test.go`
- Modify: `go.mod`

- [ ] Add Bubble Tea/Bubbles dependencies.
- [ ] Implement a compact inline progress renderer with title, step counter, progress bar, step text, and optional detail.
- [ ] Add a no-op fallback reporter for non-TTY cases and startup failures.
- [ ] Add unit tests for progress percentage, compact line count, and fallback behavior.

### Task 2: Wire Progress Through Host Startup Phases

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`

- [ ] Introduce a startup phase list and reporter lifecycle in `HostRunner.Run`.
- [ ] Emit updates around config/env resolution, kernel/image/rootfs prep, workspace prep, volume prep, metadata image creation, service startup, and VM handoff.
- [ ] Ensure the renderer stops before PTY attach and before error reporting.
- [ ] Add tests for phase order and stop-on-error behavior.

### Task 3: Verify End-to-End Behavior

**Files:**
- Modify: `README.md`

- [ ] Document the interactive startup indicator briefly in the README.
- [ ] Run `go test ./...`.
- [ ] Run `cd guest && go test ./...`.
- [ ] Build `./cmd/keel` to verify dependency wiring.
- [ ] Commit and push the finished feature.
