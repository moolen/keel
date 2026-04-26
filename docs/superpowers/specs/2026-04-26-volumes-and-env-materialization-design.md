# Volumes And Env Materialization Design

## Goal

Add two new runtime capabilities to Keel:

- pass additional host volumes into the VM
- pass environment variables into the workload from static values, host environment lookups, or host-side commands

The implementation should keep the hypervisor abstraction clean and avoid leaking resolved environment values through kernel args.

## Configuration

Add first-class `volumes` and structured `env` sections:

```yaml
workspace:
  mount: .
  target: /workspace
  sync_back: true

volumes:
  - source: ./.cache/pip
    target: /cache/pip
    read_only: false
    sync_back: false
    ownership: process

  - source: ~/.gitconfig
    target: /home/app/.gitconfig
    read_only: true

env:
  static:
    TERM: xterm-256color
    PIP_CACHE_DIR: /cache/pip

  from_host:
    GITHUB_TOKEN: GITHUB_TOKEN
    SSH_AUTH_SOCK: SSH_AUTH_SOCK

  from_command:
    BUILD_SHA:
      command: ["git", "rev-parse", "HEAD"]
    OP_SESSION:
      shell: "op read op://dev/session/token"
```

## Environment Model

Environment values are resolved on the host before VM boot.

Supported sources:

- `env.static`: literal values
- `env.from_host`: `guest_env_name -> host_env_name`
- `env.from_command`: `guest_env_name -> resolver`

Resolver forms:

- `command: ["prog", "arg1", ...]`
- `shell: "..."`, executed as `/bin/sh -lc`

Resolution rules:

- missing `from_host` variables are errors
- `from_command` must choose exactly one of `command` or `shell`
- non-zero command exit is an error
- one trailing newline is trimmed from stdout
- embedded newlines are rejected

Resolution order:

1. `env.static`
2. `env.from_host`
3. `env.from_command`
4. Keel runtime proxy overrides inside the guest

Keel-injected proxy variables stay authoritative so user configuration cannot disable the network path by overriding `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

## Volume Model

Each configured volume is materialized into its own ext4 image and attached to the VM as an extra block device.

Supported source kinds:

- host directories
- single host files

Directory volumes mount directly to the requested guest target.

File volumes are staged into a tiny filesystem image, mounted at a private guest path, and then bind-mounted to the requested guest file target. This allows targets like `/home/app/.gitconfig` without exposing Firecracker details in the user config.

Volume fields:

- `source`: host file or directory path
- `target`: absolute guest path
- `read_only`: mount read-only in guest
- `sync_back`: copy changes back on exit for writable volumes
- `ownership`:
  - `host`: preserve image ownership as created on the host
  - `process`: chown the mounted target root to the configured workload UID/GID before exec

`ownership: process` requires `process.uid` and `process.gid`.

## Boot Metadata Transport

Keel should stop growing kernel args for structured runtime data.

Instead, the host prepares a small read-only metadata image that contains `boot.json`. The VM attaches that image as an extra drive immediately after the workspace drive.

The metadata manifest carries:

- workload command
- working directory
- resolved environment variables
- process credential config
- attached volume metadata

Example shape:

```json
{
  "command": ["/bin/sh", "-lc", "echo hi"],
  "cwd": "/workspace",
  "env": {
    "TERM": "xterm-256color",
    "BUILD_SHA": "abc123"
  },
  "process": {
    "uid": 1000,
    "gid": 1000,
    "supplementary_gids": [27]
  },
  "volumes": [
    {
      "device": "/dev/vdd",
      "target": "/cache/pip",
      "kind": "dir",
      "read_only": false,
      "sync_back": false,
      "ownership": "process"
    }
  ]
}
```

Kernel args remain only for small bootstrap values:

- guest rootfs boot args
- network args
- Firecracker metadata drive device path
- existing feature payload during the transition

## Guest Runtime Flow

Guest startup becomes:

1. mount core filesystems
2. read kernel cmdline for minimal bootstrap values
3. mount the metadata drive
4. read `boot.json`
5. mount workspace
6. mount additional volumes
7. start guest DNS/TCP proxy services and features
8. construct final workload env from the manifest and apply proxy overrides
9. apply optional ownership fixes for `ownership: process`
10. drop privileges for the final workload command if configured
11. exec the workload through the PTY path

## Sync-Back Behavior

Workspace sync remains unchanged.

Volume sync-back is independent per volume:

- writable directory volumes may sync back like the workspace image flow
- writable file volumes copy the staged payload file back to the host source path
- read-only volumes never sync back

## Validation

- `volume.target` must be absolute
- `volume.source` must exist
- `sync_back` is invalid on read-only volumes
- `ownership` must be `host` or `process`
- `ownership: process` requires configured workload UID/GID
- `env.from_command` entries must set exactly one of `command` or `shell`

## Security Notes

- `from_command` executes on the host in the user context
- resolved env values must not be printed in logs or dry-run output
- environment values move through the metadata image, not kernel args
- metadata and volume images are cleaned up with other runtime assets

## Non-goals

- implicit host env passthrough
- shell interpolation inside `env.static`
- recursive ownership remapping of all mounted content
- moving all existing feature transport out of kernel args in this pass
