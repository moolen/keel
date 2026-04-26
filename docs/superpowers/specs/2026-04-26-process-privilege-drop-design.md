# Process Privilege Drop Design

## Goal

Allow Keel to keep guest bootstrap and platform services running as root while optionally dropping privileges for the final workload command.

## Configuration

Add a new config section:

```yaml
process:
  uid: 1000
  gid: 1000
  supplementary_gids: [27]
```

V1 is numeric-only on purpose. It avoids guest passwd/group lookups and keeps behavior deterministic across images.

## Runtime Model

- guest bootstrap remains root
- guest DNS/TCP proxies remain root
- guest feature setup remains root
- only the final command launched through the PTY path can drop privileges

Implementation point:

- `guest/internal/pty` applies `cmd.SysProcAttr.Credential`

## Validation

- if `uid` is set, `gid` must also be set
- if `gid` is set, `uid` must also be set
- `supplementary_gids` require both `uid` and `gid`
- negative values are rejected

If `process` is omitted, behavior remains unchanged and the command runs as root.

## Testing

Add tests for:

- config parsing and defaults
- invalid partial config
- guest launch path with explicit credentials
- guest launch path with no credentials

## Non-goals

- user/group name lookup
- automatic home directory inference
- changing file ownership of the mounted workspace
