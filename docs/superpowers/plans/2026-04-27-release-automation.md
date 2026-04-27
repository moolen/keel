# Release Automation Implementation Plan

**Goal:** Add a GitHub Actions release workflow that triggers on pushes to `master`, derives the next semantic version from all pushed commit messages, creates the tag, builds `keel` and `keel-agent`, and publishes a GitHub Release with those assets.

## Files

- Add: `.github/workflows/release.yml`
- Optional modify: `README.md` only if a small release-process note is needed

## Tasks

### Task 1: Add release workflow

- [ ] Create `.github/workflows/release.yml`
- [ ] Trigger on `push` to `master`
- [ ] Grant only `contents: write`
- [ ] Checkout full history and tags
- [ ] Set up Go using `go.mod`

### Task 2: Compute next version from pushed commits

- [ ] Inspect `${{ github.event.before }}..${{ github.sha }}`
- [ ] Parse all commit messages in the range
- [ ] Promote bump level using Conventional Commit rules
- [ ] Read latest `v*` tag and compute next semver
- [ ] Fail if computed tag already exists

### Task 3: Build release assets

- [ ] Build host `keel` as `dist/release/keel-linux-amd64`
- [ ] Build guest `keel-agent` as `dist/release/keel-agent-linux-amd64`

### Task 4: Publish GitHub Release

- [ ] Create and push the new tag
- [ ] Publish a GitHub Release with generated notes
- [ ] Upload both built binaries as release assets

### Task 5: Verify workflow syntax and repo tests

- [ ] Review workflow for shell and GitHub Actions correctness
- [ ] Run repository test suite if local changes touch build assumptions
- [ ] Confirm working tree is clean except intended changes
