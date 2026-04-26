# Process Privilege Drop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional workload privilege dropping so the final command can run as a configured UID/GID while guest bootstrap remains root.

**Architecture:** Extend the shared config with a numeric `process` section and pass it through to the guest boot command path. Apply credentials only at the final `exec.Command` boundary in `guest/internal/pty`, leaving workspace mount, proxies, feature setup, and PID 1 responsibilities unchanged.

**Tech Stack:** Go, shared config loader, guest PTY launcher, Go unit tests.

---

### Task 1: Add Config Model And Validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader_test.go`

- [ ] Add `ProcessConfig` with `uid`, `gid`, and `supplementary_gids`.
- [ ] Add loader/default tests for omitted config and parsed numeric config.
- [ ] Add validation tests for invalid partial config.

### Task 2: Thread Process Config Into Guest Boot

**Files:**
- Modify: `guest/internal/agent/agent.go`
- Test: `guest/internal/agent/agent_test.go`

- [ ] Extend boot config to carry process settings.
- [ ] Add tests for parsing and propagation of process config from the kernel command line.

### Task 3: Drop Privileges For Final Command Only

**Files:**
- Modify: `guest/internal/pty.go`
- Test: `guest/internal/pty_test.go`

- [ ] Add failing tests for configured credentials versus default root behavior.
- [ ] Apply `cmd.SysProcAttr.Credential` only when process config is present.
- [ ] Keep command launching behavior otherwise unchanged.

### Task 4: Verify And Commit

**Files:**
- Modify: `docs/superpowers/specs/2026-04-26-process-privilege-drop-design.md`
- Modify: `docs/superpowers/plans/2026-04-26-process-privilege-drop.md`

- [ ] Run focused tests first.
- [ ] Run `go test ./...` and `cd guest && go test ./...`.
- [ ] Commit and push the finished feature.
