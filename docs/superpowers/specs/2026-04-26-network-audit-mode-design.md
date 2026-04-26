# Network Audit Mode Design

## Goal

Add a global network audit mode that keeps all policy evaluation active, allows traffic to proceed, and reports policy violations as `would_deny` in shutdown summaries.

## Scope

Applies to the existing DNS, TCP/TLS, and HTTP MITM policy stack.

- `network.audit: false` or omitted keeps current enforcement behavior.
- `network.audit: true` preserves inspection, preserves decision reasons/rules, and converts policy denies into runtime-allowed `would_deny` results.

## Configuration

Audit mode is a new orthogonal flag:

```yaml
network:
  audit: true
```

It does not replace `network.mode` because transport wiring and audit semantics are separate concerns.

## Decision Model

The policy layer remains the source of truth.

`Decision` is extended so it can represent:

- enforced allow
- enforced deny
- audit-only allow that would have been denied

That state is then consumed by DNS/TCP/MITM code without reimplementing policy logic in each proxy.

## Runtime Semantics

- DNS queries that would be denied are forwarded in audit mode and summarized as `would_deny`.
- TCP/TLS flows that would be denied are tunneled in audit mode and summarized as `would_deny`.
- HTTP requests that would be denied are proxied upstream in audit mode and summarized as `would_deny`.
- Inspection-required paths still run. Audit mode does not bypass MITM/TLS parsing because the point is to show what enforcement would have done.

## Reporting

Shutdown summaries gain a third policy state:

```text
dns  example.com:53 policy=would_deny count=4
tcp  api.github.com:443 policy=allowed count=2
http api.github.com POST /repos/123 policy=would_deny count=1
```

## Host Boundary

Audit mode does not weaken host-side default-deny networking outside the policy proxies. It only changes how policy decisions are enforced inside the existing DNS/TCP/MITM chokepoints.

## Testing

Add or extend tests for:

- config parsing/defaults for `network.audit`
- policy decision audit conversion
- summary labeling for `would_deny`
- DNS audit path: denied query becomes allowed-at-runtime + `would_deny`
- TCP/TLS audit path: denied flow becomes allowed-at-runtime + `would_deny`
- HTTP MITM audit path: denied request succeeds and is summarized as `would_deny`
