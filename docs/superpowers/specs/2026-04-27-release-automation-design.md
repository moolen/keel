# Release Automation Design

## Goal

Add a GitHub Actions workflow that creates a new GitHub Release whenever changes land on `master`. The workflow must derive the semantic version bump from all commit messages in the pushed range using Conventional Commit semantics, create the next `vX.Y.Z` tag, build the project binaries, and upload them to the release.

## Constraints

- Trigger on pushes to `master`.
- Inspect all commits in the push range, not just the merge commit.
- Bump rules:
  - `BREAKING CHANGE` footer or `type!:` header => major
  - `feat:` => minor
  - everything else => patch
- If no `v*` tag exists yet, start from `v0.1.0`.
- Publish a GitHub Release with generated notes.
- Build and upload both binaries:
  - host `keel`
  - guest `keel-agent`
- Keep the implementation lightweight; do not introduce GoReleaser.

## Approach

Use a single workflow file under `.github/workflows/` with inline shell logic for version calculation. The workflow checks out the full git history and tags, computes the bump from `${{ github.event.before }}..${{ github.sha }}`, creates and pushes the next tag, builds the binaries with the same commands already used in CI, and publishes a GitHub Release with attached assets.

## Workflow Design

### Trigger

- `push` on `master`

### Permissions

- `contents: write`

No broader permissions are required.

### Version Derivation

1. Resolve the latest `v*` tag with `git tag --list 'v*' --sort=-version:refname | head -n1`.
2. If none exists, use base version `v0.0.0` and then apply the bump, which yields `v0.1.0` for the first release because the default bump level is at least patch and a `feat:` commit promotes to minor.
3. Read all commit subjects and bodies in the pushed range.
4. Determine the highest bump level across the range:
   - major beats minor
   - minor beats patch
5. Compute the next semantic version.
6. If the computed tag already exists, fail rather than silently reusing it.

### Build Outputs

The workflow should build:

- `dist/release/keel-linux-amd64`
- `dist/release/keel-agent-linux-amd64`

This keeps the asset names explicit and stable.

### Release Publishing

Use `gh release create` with:

- the computed tag
- `--generate-notes`
- the built asset paths

The workflow authenticates with the default `GITHUB_TOKEN`.

## Failure Handling

- Fail if the push range cannot be inspected.
- Fail if semver parsing fails.
- Fail if the tag already exists.
- Fail if either build command fails.
- Fail if release creation fails.

## Testing Strategy

- Keep the version-calculation logic in shell within the workflow.
- Validate the workflow by reviewing the script logic and by relying on repository CI plus GitHub Actions execution for runtime verification.
- Ensure the workflow uses the same `go build` shape already exercised by `ci.yml`.

## Scope

In scope:

- release workflow
- semantic version bumping from commit messages
- building and uploading `keel` and `keel-agent`

Out of scope:

- changelog files committed to the repo
- multi-platform packaging
- checksums, SBOMs, signatures
- GoReleaser adoption
