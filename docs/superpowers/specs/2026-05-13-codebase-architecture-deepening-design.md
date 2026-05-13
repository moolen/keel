# Codebase Architecture Deepening Design

## Goal

Improve Keel's architecture by deepening the modules around runtime execution, runtime asset materialization, network runtime wiring, ext4 image operations, and feature contracts while preserving current behavior.

The work will be delivered as staged vertical slices. Each slice should leave the repository in a working state before the next begins.

## Context

Keel runs a command inside a Firecracker microVM, prepares a writable workspace image, wires host-side network policy proxies, injects guest runtime assets, and syncs changes back to the host. The existing architecture already has useful modules for config, VM configuration, network policy, image preparation, workspace preparation, volumes, and guest features.

The main friction is that `internal/cli/host_runner.go` coordinates too many responsibilities directly. It prepares runtime assets, translates config into network policy structures, starts proxies, owns VM handoff, manages sync-back, prepares feature config, reports progress, and exposes many injection hooks for tests. This makes the `HostRunner` interface broad and keeps unrelated test setup concentrated in `host_runner_test.go`.

## Principles

- Preserve behavior first. These are refactors, not user-facing feature changes.
- Work in vertical slices so each step is testable and reviewable.
- Move responsibilities behind deeper module interfaces only where the deletion test shows that callers would otherwise need to duplicate real complexity.
- Keep existing domain names where they are clear: runtime assets, workspace image, rootfs, boot manifest, network services, feature config, and VM.
- Avoid speculative interfaces. A seam should earn its keep through actual callers, test adapters, or distinct host/runtime adapters.

## Approach

Use staged vertical slices in this order:

1. Runtime asset materialization
2. Network runtime wiring
3. Ext4 image operations
4. Runtime runner cleanup
5. Feature contract cleanup

This order moves the largest operational responsibilities out of `HostRunner` before reshaping lower-level helpers or the feature model. It also keeps risk bounded: every slice can migrate a focused set of tests and leave the public CLI behavior unchanged.

## Slice 1: Runtime Asset Materialization

Create a deeper runtime asset module that owns preparing `vm.RuntimeAssets` from `config.Config`.

The module should own:

- kernel resolution
- image cache layout resolution and refresh decisions
- runtime rootfs copy and growth
- guest agent injection
- guest trust injection
- feature rootfs preparation
- workspace image creation
- volume image creation
- boot manifest construction and writing
- runtime and control directory layout
- runtime capacity checks
- cleanup of partially prepared assets on error

`HostRunner` should call this module through a small interface such as "prepare runtime assets" and receive `vm.RuntimeAssets`. The exact package name should be chosen during implementation, but `internal/runtime` is the default candidate.

Tests should move asset-preparation behavior out of broad runner tests and into focused tests around the new module interface. Existing runner tests should keep only end-to-end orchestration expectations.

## Slice 2: Network Runtime Wiring

Move network service construction and startup out of `HostRunner`.

The deeper network runtime module should own:

- converting `config.NetworkConfig` into `network.PolicyConfig`
- creating the tracker, summary, event logger, policy engine, DNS proxy, and TCP proxy
- deciding whether MITM CA material is required
- loading or creating MITM CA material
- starting DNS and TCP services against Unix socket paths
- starting DNS and TCP services against `hypervisor.VM` listeners
- readiness checks and cleanup

`HostRunner` should ask this module to start network services for a prepared VM/runtime and receive a cleanup function plus summary. The module can expose separate adapters for Unix socket startup and VM listener startup if that keeps the interface clearer.

This preserves `internal/network` as the owner of policy and proxy behavior, while making CLI/runtime orchestration independent of DNS/TCP construction details.

## Slice 3: Ext4 Image Operations

Introduce a focused ext4 image module for repeated filesystem-image operations.

The module should own behavior that is currently spread across rootfs, workspace, volume, boot manifest, and guest injection paths:

- creating sparse ext4 images from staged directories
- estimating image size where appropriate
- sparse file copying
- mounting images read-only with the existing journal-recovery fallback where needed
- unmount cleanup
- debugfs directory creation, file writes, file removal, and file reads

Existing modules should remain domain adapters:

- `workspace` owns workspace diffing and sync semantics
- `volume` owns file-versus-directory volume semantics
- `image` owns OCI pull/cache/rootfs semantics
- `bootmanifest` owns manifest encoding

The ext4 module should not absorb those domain concepts. It should only remove duplicated operational filesystem knowledge.

## Slice 4: Runtime Runner Cleanup

After runtime assets and network services are deeper modules, simplify `HostRunner`.

The target responsibilities for `HostRunner` are:

- handle dry-run output
- resolve runtime config
- create progress reporting
- prepare runtime assets
- start network services
- run the VM
- sync workspace and volumes back
- print network summary
- translate VM attachment failures into useful CLI errors

Progress reporting can stay in `cli` initially because it is user-interface behavior. The important change is that `HostRunner` should no longer know how to build every runtime artifact or every network proxy dependency.

## Slice 5: Feature Contract Cleanup

Clarify host and guest feature ownership without changing the current kernel/JSON transport unless a simpler compatible shape falls out naturally.

The current Docker feature has:

- host-side validation and rootfs checks in `internal/features`
- runtime feature config mutation in `HostRunner`
- guest-side startup behavior in `guest/internal/features`
- loose `map[string]any` config at the seam

The cleanup should centralize feature validation/defaulting and make host and guest responsibilities explicit. Docker can remain the only initial feature. The goal is to make future features less likely to duplicate ad hoc config parsing or spread host/guest behavior through unrelated modules.

## Testing

Each slice should use test-first changes:

- Add focused tests for the new module interface before implementation.
- Watch those tests fail for the expected reason.
- Move or reduce existing broad `HostRunner` tests only after the focused tests pass.
- Keep behavior tests around public CLI and runner flows where they still provide useful coverage.
- Run focused package tests after each slice, then run the full Go test suite when Go is available.

The current environment used for this design did not have `go` on `PATH`, so implementation work should first establish a baseline in an environment where `go test ./...` can run.

## Non-Goals

- No CLI behavior changes.
- No network policy semantics changes.
- No VM boot behavior changes.
- No new feature system beyond clarifying the current Docker feature contract.
- No broad package rename unless it falls directly out of one staged slice.

## Open Implementation Decisions

- Exact package names for runtime asset and network runtime modules.
- Whether ext4 helpers live under `internal/ext4`, `internal/image/ext4`, or another existing package path.
- How much of the existing `HostRunner` injection surface remains after focused module tests take over.

These decisions should be made in the implementation plan with file-level tasks and tests.
