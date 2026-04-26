# Network Audit Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a global `network.audit` mode that allows traffic while reporting policy violations as `would_deny`.

**Architecture:** Keep enforcement logic centralized in `internal/network`. Extend `Decision` and summary labeling so proxies continue using the same decision flow, but audit mode changes deny behavior from blocking to pass-through. Surface the new config flag through loader/defaults and add focused tests around DNS, TCP/TLS, and HTTP MITM behavior.

**Tech Stack:** Go, existing config loader, DNS/TCP/MITM proxy stack, Go unit tests.

---

### Task 1: Add Config Coverage

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader.go`
- Test: `internal/config/loader_test.go`

- [ ] Add `NetworkConfig.Audit bool` and loader/default coverage.
- [ ] Add config tests for default `false` and parsed `true`.

### Task 2: Add Audit-Aware Decisions And Summary Labels

**Files:**
- Modify: `internal/network/policy.go`
- Modify: `internal/network/summary.go`
- Test: `internal/network/policy_test.go`

- [ ] Extend `Decision` so it can represent runtime allow plus `would_deny`.
- [ ] Thread `Audit` through `PolicyConfig`.
- [ ] Convert deny decisions to audit-allow inside policy evaluation.
- [ ] Add unit tests for audit conversion and summary labeling.

### Task 3: Apply Audit Mode In Proxies And MITM HTTP

**Files:**
- Modify: `internal/network/dns.go`
- Modify: `internal/network/tcp.go`
- Modify: `internal/network/mitm.go`
- Test: `internal/network/mitm_test.go`

- [ ] Keep proxies on the existing decision path and rely on `Decision.Allowed` plus audit metadata.
- [ ] Ensure HTTP MITM deny responses become pass-through when audit mode is enabled.
- [ ] Add tests proving denied HTTP requests succeed in audit mode and are summarized as `would_deny`.

### Task 4: Surface Audit Mode In Host Wiring

**Files:**
- Modify: `internal/cli/host_runner.go`
- Test: `internal/cli/host_runner_test.go`

- [ ] Pass `network.audit` into `PolicyConfig`.
- [ ] Add a startup warning to stderr when audit mode is enabled.
- [ ] Add host-runner tests for audit wiring if needed.

### Task 5: Verify And Commit

**Files:**
- Modify: `docs/superpowers/specs/2026-04-26-network-audit-mode-design.md`
- Modify: `docs/superpowers/plans/2026-04-26-network-audit-mode.md`

- [ ] Run targeted tests first, then `go test ./...`.
- [ ] Run guest tests if touched indirectly.
- [ ] Commit with a focused message and push to `main`.
