# Containment Hardening Design

Date: 2026-04-26

## Goal

Tighten Keel's VM containment model so that:

- named network access is explicit, port-scoped, and fail-closed
- direct IP egress is denied by default
- cached base images are immutable across runs
- untrusted workloads run unprivileged by default

This design intentionally prioritizes strict isolation over backward compatibility.

## Problems To Fix

The current implementation has three material gaps:

1. DNS correlation is treated as a broad allow signal for an IP, which over-authorizes shared IP destinations.
2. The cached rootfs image is used as the writable VM root disk, so one run can persist changes into future runs.
3. The final workload runs as root unless the operator explicitly configures a different UID/GID.

## Scope

In scope:

- network policy model redesign
- config schema changes for network rules
- DNS/TCP/TLS decision model changes
- immutable cached base image handling
- default non-root workload execution
- tests and docs covering the new semantics

Out of scope:

- preserving the old network config model
- header/body/query aware policy
- replacing the guest bootstrap model where PID 1 starts as root
- a block-level overlay implementation for the first storage hardening pass

## High-Level Design

Keel should move to a stricter split:

- cached image artifacts are immutable preparation outputs
- each run gets its own writable root disk derived from the immutable base
- network policy is expressed as explicit endpoint rules instead of separate DNS/TLS allowlists
- the final workload command runs as an unprivileged user unless root is explicitly requested

The resulting model is easier to reason about:

- `host + port` means DNS may resolve that host and traffic may connect only to the resolved IPs for that host on that port
- TLS traffic for a named endpoint must present matching SNI unless the rule disables that requirement
- raw IP traffic is denied unless a `cidr + port` rule allows it
- the base image cache never becomes mutable runtime state

## Network Policy Model

### Configuration

Replace the current normal named-egress model with two explicit rule types:

```yaml
network:
  audit: false
  deny_unresolved_hosts: true

  endpoints:
    - host: api.github.com
      port: 443

    - host: *.githubusercontent.com
      port: 443
      tls:
        require_sni_match: true

    - host: packages.example.internal
      port: 8443
      tls:
        require_sni_match: false

  ip_rules:
    - cidr: 10.20.0.0/16
      port: 5432
```

### Rule Semantics

`network.endpoints`

- Defines normal named outbound access.
- Each rule is `host pattern + port`.
- `host` uses the same glob-style pattern matching Keel already uses.
- `port` is mandatory.
- The rule authorizes:
  - DNS resolution for matching hostnames
  - TCP connections only to IPs resolved for that hostname
  - only on the configured port

`network.endpoints[].tls.require_sni_match`

- Defaults to `true` for TLS ports.
- When `true`, a TLS connection matched through an endpoint rule must present SNI matching the resolved hostname.
- When `false`, Keel still uses the endpoint rule for DNS and IP correlation but does not require SNI equality for that rule.

`network.ip_rules`

- Defines the only allowed direct-IP egress path.
- Each rule is `cidr + port`.
- Raw IP connections that do not match an `ip_rules` entry are denied.

`network.deny_unresolved_hosts`

- Defaults to `true`.
- If a hostname is not covered by `network.endpoints`, DNS queries for it are denied and TCP connections relying on it cannot be authorized.

### Removed Configuration

Remove these fields from the primary policy model:

- `network.dns.allowed`
- `network.dns.denied`
- `network.tls.allowed_sni`
- `network.tls.denied_sni`
- `network.tcp.allowed_cidrs`
- `network.tcp.denied_cidrs`
- `network.deny_if_no_sni`

`network.http` and `network.mitm` stay, but they become narrower second-layer controls on top of the new endpoint/IP transport policy.

## DNS Decision Model

DNS is no longer an independent allow plane. It is a preparatory step for endpoint rules.

For each DNS query:

1. Normalize the requested hostname.
2. Match it against `network.endpoints`.
3. If no endpoint rule matches, refuse the query.
4. If one or more endpoint rules match, resolve upstream and record:
   - hostname
   - resolved IP
   - expiry
   - the specific endpoint rules that this answer may satisfy

Important semantic change:

- observing `api.github.com -> 140.82.112.6` does **not** mean `140.82.112.6` is now broadly allowed
- it only means that connections to `140.82.112.6` may satisfy endpoint rules that matched `api.github.com`

The tracker must therefore stop returning a flat list of domains for an IP. It should return active endpoint authorizations scoped to hostname, port, expiry, and rule identity.

## TCP/TLS Decision Model

### Named Destination Flow

For a TCP flow to destination `IP:port`:

1. If the client connected by raw IP and there is no matching `ip_rules` entry for `IP + port`, deny.
2. If there is a matching active endpoint authorization for `IP + port`, continue evaluation using that endpoint rule.
3. If no matching active endpoint authorization exists, deny.

For TLS on a named endpoint:

1. Parse client hello if present.
2. If the matched endpoint rule requires SNI equality, require a non-empty SNI equal to the authorized hostname.
3. If SNI parsing fails on a flow that requires inspection, deny.
4. If the rule disables SNI matching, skip the equality check for that rule.

Important semantic change:

- shared IPs no longer grant transitive access to arbitrary sibling hostnames
- port is always part of authorization
- DNS correlation is evidence for exactly one endpoint rule match, not a reusable IP trust primitive

### Direct IP Flow

If the guest opens a connection directly to an IP:

- allow only when a `network.ip_rules` entry matches `cidr + port`
- otherwise deny

Direct IP egress never inherits authorization from previous DNS answers.

## MITM And HTTP Policy Interaction

The new transport policy remains the first gate.

Order of evaluation:

1. endpoint/IP transport rule
2. TLS/SNI validation required by that transport rule
3. MITM eligibility
4. HTTP policy if the flow is intercepted and parsed as HTTP

This preserves the current architecture goal that HTTP policy narrows transport authorization rather than replacing it.

## Storage Model

### Immutable Base Image

The cache directory should contain only immutable prepared artifacts:

- OCI tarball
- immutable prepared base rootfs image
- guest-agent digest / metadata files tied to the base image

The cached base image must never be attached to the VM as the writable root disk.

### Per-Run Writable Root Disk

For each run:

1. Resolve the cached immutable base rootfs.
2. Copy it into the runtime directory as that run's writable root disk.
3. Boot Firecracker from the per-run writable copy.
4. Delete the runtime copy during cleanup.

This is the first hardening step. It is intentionally simpler than implementing copy-on-write block overlays. The extra I/O is acceptable for now because it closes the persistence gap with lower complexity and less risk.

### Preparation-Time Mutation

Guest-agent injection, CA injection, and feature rootfs preparation still operate on the cached base image, but only during image preparation or refresh. Runtime execution never mutates the cached base.

That yields a stable lifecycle:

- image prep mutates cache
- runtime copies cache
- VM mutates runtime copy only

## Process Privilege Model

### Default Workload Identity

The final workload command should run as an unprivileged default identity when `process` is omitted.

Recommended default:

- UID `65532`
- GID `65532`
- no supplementary groups

This keeps guest bootstrap, filesystem mounts, proxies, and feature startup as root, but executes the untrusted command with reduced privilege.

### Explicit Root Opt-In

Root execution should become explicit configuration, not the default.

Examples:

- omitted `process` => run as default unprivileged identity
- `process.uid: 0`, `process.gid: 0` => explicit root opt-in

### Volume Ownership

Existing `volume.ownership=process` semantics continue to work, but now the default process identity is the unprivileged default instead of implicit root. Validation should ensure ownership behavior remains predictable for omitted `process`.

## Runtime Flow

The full runtime becomes:

1. resolve config
2. resolve immutable cached base image
3. prepare per-run runtime directory
4. copy cached base image to per-run root disk
5. prepare workspace and metadata images
6. boot VM with:
   - immutable-prepared content in the runtime root disk copy
   - writable workspace image
   - writable or read-only attached volumes
7. guest bootstrap runs as root:
   - mount filesystems
   - start DNS proxy
   - start TCP proxy
   - start optional guest features
8. final command executes as default unprivileged user unless config explicitly overrides it

## Error Handling

Fail closed in these cases:

- hostname not covered by any endpoint rule
- resolved IP used on a different port than the endpoint rule allows
- direct IP connection without matching `ip_rules`
- missing or mismatched SNI on a rule requiring SNI validation
- TLS inspection failure on a flow that requires inspection
- inability to create the per-run writable root disk

Operationally useful errors should state the denied dimension:

- host not allowed
- port not allowed
- IP not authorized for this host
- direct IP egress requires `ip_rules`
- SNI mismatch for endpoint rule

## Testing Strategy

### Network

Add tests proving:

- allowed hostname on allowed port succeeds
- allowed hostname on different port is denied
- shared IP does not authorize sibling hostname
- direct IP connect is denied by default
- direct IP connect succeeds only with matching `cidr + port`
- TLS SNI is required by default for endpoint TLS rules
- per-rule SNI disable works only for that rule
- DNS queries for non-endpoint hosts are refused

### Storage

Add tests proving:

- cached base rootfs is not used directly as the VM root disk
- each run creates a distinct runtime root disk path
- mutations to the runtime root disk do not affect the cached base image

### Process

Add tests proving:

- omitted `process` produces the default unprivileged workload identity
- explicit root config still runs as root
- `volume.ownership=process` uses the default identity when `process` is omitted

## Migration Stance

This design is intentionally not backward compatible.

Old configs using separate DNS/TLS/TCP allowlists should fail validation with a targeted error that tells the operator to migrate to:

- `network.endpoints`
- `network.ip_rules`

The point of the change is to eliminate ambiguous policy semantics rather than preserve them.

## Implementation Notes

Recommended refactoring direction:

- replace the old `PolicyConfig` shape with endpoint/IP rule structures
- replace the tracker's `ip -> []domain` state with `ip + port` eligible authorizations derived from endpoint rules
- make `prepareAssets` produce a cached immutable base path and a per-run root disk path separately
- mark the runtime root disk as the attached writable root drive
- make config defaults populate the unprivileged workload identity when omitted

## Security Outcome

After this change:

- named egress is explicit, port-scoped, and non-transitive across shared IPs
- direct IP traffic is denied unless explicitly allowed
- one VM run cannot persist rootfs mutations into later runs through the shared cache
- untrusted workloads lose root by default while bootstrap services retain the privileges they need
