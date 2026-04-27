# Keel Devtools Image Design

## Goal

Add a root-level `Dockerfile` that builds a slim but feature-rich OCI image for coding agents and Firecracker guest workflows, then publish that image to GHCR from GitHub Actions.

The image name will be:

- `ghcr.io/moolen/keel-devtools`

## Requirements

- Use `debian:trixie-slim` as the base image.
- Install a broad development and operations toolchain suitable for coding agents.
- Include the Docker daemon, not just the Docker CLI.
- Create and push the image to GHCR from CI on `main` and from the release workflow on version releases.
- Build preview images on pull requests.
- Keep the image practical and dependable rather than aggressively minimizing size.

## Tooling Scope

The image should include at least:

- core shell and editor tools:
  - `bash`
  - `git`
  - `ripgrep`
  - `make`
  - `curl`
  - `wget`
  - `jq`
  - `unzip`
  - `xz-utils`
  - `tar`
  - `less`
  - `vim-tiny`
- networking and debugging:
  - `socat`
  - `netcat-openbsd`
  - `strace`
  - `procps`
  - `ca-certificates`
- build chain:
  - `gcc`
  - `g++`
  - `pkg-config`
  - common development libraries needed for native builds
- language runtimes and SDKs:
  - Go
  - Python 3
  - `pip`
  - `venv`
- cloud and platform tooling:
  - `awscli`
  - `gh`
- agent tooling:
  - `opencode`
- supply-chain and container tooling:
  - Docker engine and CLI
  - `grype`
  - `golangci-lint`
  - `govulncheck`
  - `crane`
  - `hadolint`
  - `yq`

## Base Image Choice

Use `debian:trixie-slim`.

Rationale:

- newer package set than Bookworm while still staying in a Debian family that is predictable for CI and dev tooling
- broad compatibility with Docker engine, compilers, Python, Go, and common Linux utilities
- better fit than Alpine for a “toolbox” image because glibc-based packages and vendor binaries are less likely to need adaptation

## Image Design

### Package Strategy

Use a single-stage Dockerfile based on `debian:trixie-slim`.

Install Debian-packaged tools where they are stable and current enough:

- shell, VCS, networking, compiler, Python, AWS CLI, Docker engine, and other common utilities

Install vendor binaries directly for tools where upstream release artifacts are the normal distribution path or where repo packages are inconsistent:

- `opencode`
- `yq`
- `grype`
- `golangci-lint`
- `govulncheck`
- `crane`
- `hadolint`

This keeps the image build understandable while avoiding unnecessary source builds inside the Dockerfile.

### User Model

Create a non-root default user for agent sessions, while leaving root available.

Recommended default:

- user: `agent`
- uid/gid: `1000:1000`
- working directory: `/workspace`

This matches common container expectations while still allowing privileged workflows when explicitly requested.

### Docker Engine Behavior

Install Docker engine components in the image, but do not try to launch `dockerd` during image build.

The image should be suitable for:

- starting `dockerd` inside the container when the runtime grants the needed privileges
- using the Docker CLI against a mounted host socket
- reusing the same toolbox image in Firecracker-backed workflows where Docker-in-guest matters

The Docker daemon should be treated as runtime capability, not baked startup behavior.

## CI and Publish Design

### CI workflow

Extend `.github/workflows/ci.yml` with a container-image job.

Behavior:

- on pull requests:
  - build `keel-devtools`
  - validate the Dockerfile and image build
  - optionally publish preview tags if GitHub token permissions allow it
- on pushes to `main`:
  - build and push
  - publish stable rolling tags

Recommended tags on `main`:

- `ghcr.io/moolen/keel-devtools:main`
- `ghcr.io/moolen/keel-devtools:sha-<shortsha>`

### Release workflow

Extend `.github/workflows/release.yml` so that after creating the GitHub Release, it also builds and pushes release image tags.

Recommended release tags:

- `ghcr.io/moolen/keel-devtools:vX.Y.Z`
- `ghcr.io/moolen/keel-devtools:latest`

## Implementation Shape

Files expected to change:

- add `Dockerfile`
- modify `.github/workflows/ci.yml`
- modify `.github/workflows/release.yml`
- optionally update `README.md` with image usage and tags

## Validation

The implementation should validate:

- Dockerfile builds successfully locally or in CI
- CI still passes its existing test and lint jobs
- GHCR publish jobs use least-necessary permissions
- preview behavior is safe for PRs
- release workflow publishes image tags without breaking existing binary-release behavior

## Risks and Mitigations

### Image size

Risk:

- the tool set is large

Mitigation:

- stay on slim base
- use `--no-install-recommends`
- clean apt metadata
- prefer direct binary installs over extra package-manager stacks

### Runtime expectations for Docker daemon

Risk:

- users may assume Docker daemon works in unprivileged containers by default

Mitigation:

- document that the daemon is included but requires appropriate runtime privileges

### PR publish permissions

Risk:

- forked PRs may not have permission to push to GHCR

Mitigation:

- always build on PRs
- gate preview pushes on event type and token capability
- do not make PR preview publishing a hard requirement for CI success

## Out of Scope

- multi-arch image publishing in the first iteration
- SBOM generation or signing
- image vulnerability gating in CI
- splitting the toolbox into multiple images
