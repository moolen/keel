# Keel Devtools Image Implementation Plan

**Goal:** Add a root `Dockerfile` for `ghcr.io/moolen/keel-devtools` based on `debian:trixie-slim`, include the required agent/dev/container/security tooling, and build/publish the image to GHCR from CI and Release workflows.

## Files

- Add: `Dockerfile`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Optional: `README.md`

## Tasks

### Task 1: Add the devtools image

- [ ] Create a root `Dockerfile`
- [ ] Base it on `debian:trixie-slim`
- [ ] Install Debian-packaged core tooling and Docker engine
- [ ] Install vendor-distributed tools:
  - `opencode`
  - `yq`
  - `grype`
  - `golangci-lint`
  - `govulncheck`
  - `crane`
  - `hadolint`
- [ ] Create a non-root `agent` user with `/workspace` as the working directory

### Task 2: Build the image in CI

- [ ] Extend `.github/workflows/ci.yml`
- [ ] Add a Docker image job on pull requests and `main`
- [ ] Build on all PRs
- [ ] Push to GHCR on `main`
- [ ] Publish `main` and `sha-<shortsha>` tags on `main`
- [ ] Publish preview tags only when event/permissions allow it

### Task 3: Publish release image tags

- [ ] Extend `.github/workflows/release.yml`
- [ ] After the binary release succeeds, build and push the image
- [ ] Publish `vX.Y.Z` and `latest` tags to `ghcr.io/moolen/keel-devtools`

### Task 4: Verify

- [ ] Build the Dockerfile locally if possible
- [ ] Verify existing Go test/lint workflows still pass locally
- [ ] Review workflow permissions and event guards
