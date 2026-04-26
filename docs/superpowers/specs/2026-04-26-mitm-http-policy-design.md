# MITM HTTP Policy Design

Date: 2026-04-26

## Goal

Add HTTPS interception to Keel so egress policy can evolve from coarse transport controls (`dns`, `tcp`, `tls`) to application-aware HTTP controls based on:

- `host`
- `method`
- `path`

The new HTTP policy layer must not replace the current transport policy model. It must sit on top of it, so Keel keeps fail-closed behavior when interception is unavailable or incomplete.

## Scope

In scope:

- host-side MITM for eligible HTTP and HTTPS flows
- config schema for `network.mitm` and `network.http`
- HTTP policy matching on `host`, `method`, and `path`
- aggregated shutdown reporting for HTTP policy decisions
- guest CA trust installation
- Docker daemon and guest-level CA trust integration

Out of scope for v1:

- header-based rules
- body-based rules
- query-string-based rules
- full arbitrary container trust injection across every Linux distribution/base image
- replacing the existing DNS/TCP/TLS policy engine

## Design Goals

- Preserve current behavior when MITM is disabled.
- Preserve host-enforced fail-closed egress even when MITM cannot inspect a flow.
- Keep transport policy as the first gate.
- Add HTTP policy as a second, narrower gate after successful interception/parsing.
- Avoid logging secrets such as headers, tokens, bodies, or query strings.

## Configuration

The existing `network` section remains the main policy container. Two new subsections are added:

```yaml
network:
  mode: vsock
  deny_if_no_sni: false

  dns:
    allowed:
      - "*.github.com"
    denied: []

  tcp:
    allowed_cidrs: []
    denied_cidrs: []

  tls:
    allowed_sni:
      - "*.github.com"
    denied_sni: []

  mitm:
    enabled: false
    mode: optional
    on_untrusted_cert: deny
    log_requests: true
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true
    bypass:
      hosts: []
      sni: []

  http:
    default: deny
    rules:
      - action: allow
        host: "api.github.com"
        methods: ["GET"]
        paths:
          - "/repos/*"
          - "/users/*"
      - action: deny
        host: "*.github.com"
        methods: ["POST", "PUT", "PATCH", "DELETE"]
        paths:
          - "/*"
```

### Semantics

`network.mitm.enabled`

- Enables HTTP/HTTPS interception.

`network.mitm.mode`

- `optional` in v1.
- Means interception is applied where supported, without weakening lower-layer policy.
- It does not imply silent allow on inspection failure.

`network.mitm.on_untrusted_cert`

- `deny` in v1.
- If Keel cannot establish an acceptable upstream TLS session for a flow it intends to inspect, the flow is denied.

`network.mitm.ca`

- CA metadata and trust-install behavior.
- `install_system` controls guest root trust injection.
- `install_docker` controls Docker daemon and guest Docker client trust integration.

`network.mitm.bypass`

- Explicit host/SNI bypass list for flows that should remain tunneled without interception.
- These flows remain subject to transport policy but not HTTP policy.

`network.http.default`

- Default action for parsed HTTP requests after MITM succeeds.
- `deny` is the recommended default.

`network.http.rules`

- Ordered first-match rules.
- `host` uses glob matching.
- `methods` is a list of exact uppercase verbs.
- `paths` uses glob matching on normalized URL path only.
- Query strings are excluded from matching.

## Policy Evaluation Model

Evaluation order for an outbound flow:

1. DNS policy
2. TCP/TLS policy
3. MITM eligibility decision
4. HTTP policy, if and only if the flow is successfully parsed as HTTP

### Layer 1: DNS policy

- Same behavior as today.
- Domain allow/deny and response correlation remain unchanged.

### Layer 2: TCP/TLS policy

- Same coarse gate as today.
- SNI-based allow/deny remains in force.
- DNS-to-IP correlation remains in force.
- Host-level default-deny at the tap boundary remains authoritative.

### Layer 3: MITM decision

- If MITM is disabled, current TCP proxy behavior remains.
- If MITM is enabled:
  - plain HTTP can be parsed directly
  - HTTPS may be terminated by Keel and re-originated upstream
- If a flow is expected to be inspected but interception/parsing fails, the flow is denied.

### Layer 4: HTTP policy

- Applies only after successful parsing/interception.
- First matching rule wins.
- If no rule matches, `network.http.default` applies.

## Runtime Architecture

### Existing behavior to preserve

- `internal/network/tcp.go` is the current coarse host egress choke point.
- The guest proxy path and transparent redirect path both eventually funnel traffic toward host-side TCP policy enforcement.

### New architecture

Extend the current host TCP proxy pipeline instead of creating a separate proxy stack.

Recommended split:

- `internal/network/tcp.go`
  - coarse transport gate
  - flow classification
  - handoff into MITM path for eligible HTTP/HTTPS traffic

- `internal/network/mitm.go`
  - local TLS termination
  - upstream TLS initiation
  - request parsing and forwarding

- `internal/network/http_policy.go`
  - ordered `host + method + path` matcher

- `internal/network/ca.go`
  - load or mint persistent local CA
  - mint/cached leaf certs by hostname

- `internal/network/http_summary.go`
  - aggregate HTTP allow/deny outcomes

This keeps a single egress choke point and avoids dual enforcement paths.

## Host CA Model

Keel will maintain a persistent local CA under its cache/config directory.

Recommended files:

- `~/.local/share/keel/ca/ca.key`
- `~/.local/share/keel/ca/ca.crt`
- `~/.local/share/keel/ca/issued/<hostname>.crt`

Requirements:

- generate once and reuse
- leaf certs minted on demand
- SAN populated from requested host
- certificate cache keyed by hostname

Security expectations:

- CA private key must remain host-local
- guest receives trust anchor only, never the CA private key

## Guest Trust Injection

When `network.mitm.enabled=true` and `install_system=true`:

- inject the Keel CA certificate into the guest rootfs
- update guest trust store during image preparation or boot-time init

The guest side should treat CA installation as part of feature preparation, not ad hoc runtime mutation during the command itself.

## Docker Trust Integration

When `install_docker=true`:

- install CA trust for Docker daemon
- install CA trust for guest Docker client tooling
- keep current explicit proxy wiring for Docker

Limitations:

- Keel can reliably control guest system trust and guest Docker daemon/client trust
- Keel cannot guarantee universal trust injection into arbitrary container build stages in v1
- therefore Docker MITM support in v1 is:
  - required for daemon/client level
  - best-effort for arbitrary build container trust

This limitation must be documented in user-facing errors/warnings.

## Request Identity

HTTP request policy fields:

- `host`
  - from HTTP `Host` header or HTTP/2 `:authority`
- `method`
  - exact uppercase method
- `path`
  - normalized URL path only
  - query string removed before matching

Normalization rules:

- lower-case host before matching
- preserve path case
- normalize empty path to `/`

## Logging And Reporting

Default logs must not include:

- query strings
- headers
- bodies
- auth material

Shutdown summary should add HTTP rows such as:

```text
http api.github.com GET /repos/* policy=allowed count=12
http api.github.com POST /repos/* policy=denied count=2
```

Summary aggregation key:

- protocol=`http`
- host
- method
- matched path rule or observed normalized path
- allow/deny decision

## Error Handling

Required behaviors:

- MITM disabled: existing TCP proxy behavior unchanged
- MITM enabled but parsing/interception unavailable for an inspectable flow: deny
- transport policy deny before HTTP layer: deny immediately
- HTTP no-match with `default: deny`: deny
- guest CA install failure when MITM is enabled: fail run setup, do not silently continue

Recommended user-facing diagnostics:

- clear warning when Docker/container trust may be incomplete
- explicit reason when flow is denied due to inspection failure vs. policy mismatch

## Implementation Boundaries

Config changes:

- extend `internal/config/config.go` with `MITMConfig`, `MITMCAConfig`, `MITMBypassConfig`, `HTTPConfig`, `HTTPRuleConfig`
- update defaults and merge behavior in `internal/config/defaults.go` and `internal/config/loader.go`

Network changes:

- extend `internal/network.PolicyConfig`
- keep current DNS/TCP/TLS evaluation
- add HTTP rule engine without rewriting coarse transport enforcement

Image/guest changes:

- add CA asset plumbing to image/rootfs preparation
- add guest trust setup hooks
- extend Docker feature setup for daemon/client trust

## Testing Strategy

Unit tests:

- config parsing and merge behavior for new fields
- ordered HTTP rule matching
- host/method/path glob behavior
- path normalization
- MITM decision behavior for allow/deny/default paths
- CA generation/loading and leaf cert issuance

Integration tests:

- HTTPS request allowed by transport policy but denied by HTTP rule
- HTTPS request allowed by matching HTTP rule
- plain HTTP request policy behavior
- MITM-disabled behavior unchanged
- MITM-enabled setup fails if CA install cannot be completed

End-to-end tests:

- `curl https://...` through MITM with guest trust installed
- Docker daemon/client trust path smoke

## Open Constraints

These are explicit constraints, not unresolved placeholders:

- HTTP/1.1 is the minimum supported protocol for v1 policy enforcement
- HTTP/2 support is desirable but not required to land the config and enforcement model
- arbitrary container-stage CA trust remains follow-up work beyond v1

## Recommendation

Implement MITM as an extension of the current host TCP proxy, keep transport policy as the first gate, and add ordered `http` rules as the second gate. This yields a clear config model, preserves fail-closed behavior, and avoids a disruptive rewrite of the existing policy engine.
