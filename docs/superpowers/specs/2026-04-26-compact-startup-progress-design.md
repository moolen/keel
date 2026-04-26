# Compact Startup Progress Design

## Goal

Show a small, pretty terminal loading indicator during the slow pre-PTY phase of `keel`, covering image pull, workspace preparation, metadata/volume setup, and VM start.

The UI should stay compact: 3-5 lines total, with a progress bar, a short description, and a step counter like `3/8`.

## UX

The loader is inline, not fullscreen.

Target layout:

```text
keel preparing vm                              3/8
[███████████████░░░░░░░░░░░░░░░░░] 37%
preparing workspace image
pulling files and creating ext4 snapshot
```

Rules:

- 3-4 lines total
- line 1: title + step counter
- line 2: progress bar + percent
- line 3: current step title
- line 4: optional detail line
- no scrolling logs while the loader is active
- clear the loader before PTY handoff

## Trigger Conditions

Enable the loader only when:

- output stream is a TTY
- Keel is not running in `--dry-run`
- progress is still in the startup phase

Disable and fall back to current behavior when:

- stdout/stderr is redirected
- Keel is running in a non-interactive environment
- the loader cannot be started cleanly

## Scope

The loader covers only startup work in the host process:

1. resolve config
2. resolve runtime env
3. ensure kernel
4. pull/cache OCI image
5. inject guest assets and prepare rootfs features
6. prepare workspace image
7. prepare extra volumes
8. write boot metadata image
9. start VM services
10. boot VM and attach PTY

The last step completes immediately before control passes to the guest PTY.

## Architecture

Use Bubble Tea plus Bubbles for rendering:

- one tiny model
- one progress bar
- no alternate screen
- no log viewport
- host runner emits startup progress events

The progress API should stay simple:

- begin with a known total step count
- update current step title/detail
- mark steps completed in order
- stop and clear before PTY attach

## Integration Shape

Add a small progress renderer in `internal/cli`, owned by the host runner.

Recommended types:

- `startupStep`
- `startupProgress`
- `progressReporter` interface
- `bubbleProgressReporter` implementation
- `nopProgressReporter` fallback

Host runner should use explicit step updates around existing phases instead of trying to infer state from logs.

## Error Handling

- if startup fails, stop the loader first, then print the real error
- if Bubble Tea cannot start, continue without the loader
- progress reporting must never block VM startup

## Testing

Add tests for:

- TTY gating
- step-to-progress mapping
- compact renderer output shape
- host runner phase reporting order
- clean stop before PTY handoff

## Non-goals

- fullscreen TUI
- live byte-level download percentages
- startup log streaming inside the loader
- showing post-boot workload output in Bubble Tea
