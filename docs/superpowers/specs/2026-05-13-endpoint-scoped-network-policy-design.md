# Endpoint-Scoped Network Policy Design

Date: 2026-05-13

## Goal

Replace Keel's separate DNS, TCP, TLS, MITM, and HTTP policy configuration with an endpoint-scoped network policy model.

The endpoint becomes the infosec review surface:

- which host and port may be reached
- whether TLS SNI must match
- whether MITM inspection is required
- which HTTP methods and paths are allowed for that endpoint

This change is intentionally not backward compatible.

## Problems To Fix

The current model splits one outbound permission across several places:

- `network.dns.allowed` controls hostname resolution
- `network.tls.allowed_sni` controls TLS identity
- `network.tcp.allowed_cidrs` controls direct IP fallback
- top-level `network.http.rules` repeats host matching for HTTP
- top-level `network.mitm.enabled` makes inspection look global

That shape is hard to audit. A reviewer cannot look at one rule and know the full access granted to `api.github.com:443`.

The current implementation also tracks DNS as `ip -> []domain`, which makes authorization too broad for shared IPs. The intended model is `host + port` scoped authorization.

## Configuration

Use endpoint rules for named egress:

```yaml
network:
  mode: vsock
  audit: false

  endpoints:
    - host: api.github.com
      port: 443
      tls:
        require_sni_match: true
      mitm:
        required: true
      http:
        default: deny
        rules:
          - action: allow
            methods: ["GET"]
            paths: ["/repos/*", "/rate_limit"]

    - host: objects.githubusercontent.com
      port: 443
      tls:
        require_sni_match: true
      mitm:
        required: false

  ip_rules:
    - cidr: 10.20.0.0/16
      port: 5432

  mitm:
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true
```

Remove these old fields:

- `network.dns`
- `network.tcp`
- `network.tls`
- `network.deny_if_no_sni`
- top-level `network.http`
- `network.mitm.enabled`
- `network.mitm.bypass`

## Endpoint Rules

`network.endpoints[]` defines named outbound access.

Fields:

- `host`: required hostname or glob pattern, matched against DNS names and TLS SNI.
- `port`: required TCP port.
- `tls.require_sni_match`: optional bool, defaults to `true` for TLS endpoints.
- `mitm.required`: optional bool, defaults to `false`.
- `http`: optional endpoint-local HTTP policy, valid only when `mitm.required: true`.

Endpoint authorization grants exactly:

- DNS resolution for matching hostnames
- TCP connection to resolved IPs only on the endpoint port
- TLS flow only when required SNI validation succeeds
- HTTP flow only when the endpoint-local HTTP policy allows it, if MITM is required

DNS correlation is not reusable across ports or sibling hostnames on a shared IP.

## Direct IP Rules

`network.ip_rules[]` defines direct IP egress.

Fields:

- `cidr`: required CIDR range.
- `port`: required TCP port.

Direct IP rules cannot define MITM or HTTP policy because there is no named endpoint for certificate issuance or HTTP host review. If a reviewer wants HTTP policy, the destination must be expressed as an endpoint.

## MITM Model

MITM is an inspection adapter used by endpoint rules. It is not an authorization mode.

Top-level `network.mitm` configures adapter setup only:

- local CA name
- whether the CA is installed into the guest trust store
- whether the CA is installed into Docker trust paths

The policy decision lives on the endpoint:

```yaml
endpoints:
  - host: api.github.com
    port: 443
    mitm:
      required: true
```

If any endpoint has `mitm.required: true`, Keel must prepare the MITM adapter. If CA loading, CA installation, TLS termination, or upstream TLS validation fails for a required-MITM endpoint, the flow is denied.

`mitm.required: false` means Keel may pass the allowed transport flow through without HTTP inspection. It does not allow traffic that failed endpoint transport policy.

## HTTP Policy

HTTP policy lives under the endpoint it narrows:

```yaml
endpoints:
  - host: api.github.com
    port: 443
    mitm:
      required: true
    http:
      default: deny
      rules:
        - action: allow
          methods: ["GET"]
          paths: ["/repos/*"]
```

Rules do not repeat `host`; the endpoint host is the host under review.

Fields:

- `http.default`: `allow` or `deny`, defaults to `deny`.
- `http.rules[].action`: `allow` or `deny`.
- `http.rules[].methods`: optional method list. Empty means all methods.
- `http.rules[].paths`: optional glob path list. Empty means all paths.

Evaluation order:

1. endpoint/IP transport authorization
2. TLS SNI validation for endpoint traffic
3. required MITM inspection, if configured
4. endpoint-local HTTP policy

HTTP policy can only narrow access. It never grants transport access by itself.

## Runtime Behavior

DNS query for a named endpoint:

1. Normalize the requested hostname.
2. Match it against `network.endpoints[].host`.
3. If no endpoint matches, refuse the query.
4. Resolve upstream.
5. Record endpoint authorizations for returned IPs, scoped by hostname, endpoint port, expiry, and endpoint rule.

TCP flow to an IP and port:

1. If a matching endpoint authorization exists for `IP + port`, evaluate that endpoint.
2. If no endpoint authorization exists, check `network.ip_rules`.
3. If neither matches, deny.
4. If endpoint TLS validation is required, require matching SNI.
5. If endpoint MITM is required, inspect HTTP through MITM and apply endpoint-local HTTP policy.
6. Otherwise, forward the flow.

Audit mode keeps the same evaluation path but records denied decisions as `would_deny` and allows them to pass.

## Validation

Fail config validation when:

- old network fields are present
- an endpoint omits `host`
- an endpoint omits `port` or uses an invalid port
- an IP rule omits `cidr`
- an IP rule omits `port` or uses an invalid port
- an endpoint defines `http` without `mitm.required: true`
- an HTTP rule action is not `allow` or `deny`
- an HTTP default is not `allow` or `deny`

Old configs should fail with a targeted message telling the operator to migrate to `network.endpoints` and `network.ip_rules`.

## Module Shape

The deepened network policy module should expose one transport policy interface.

The implementation should hide:

- endpoint rule matching
- DNS answer observation
- endpoint authorization expiry
- direct IP rule matching
- TLS SNI validation
- audit-mode conversion
- summary rule labels

The DNS proxy should ask the module whether to resolve and then report observed answers. The TCP proxy should ask the module whether a flow may proceed and whether MITM/HTTP inspection is required.

The interface is the test surface. Tests should describe behavior in terms of endpoint authorization rather than individual DNS, TCP, and TLS helpers.

## Testing Strategy

Add tests proving:

- hostname on the configured endpoint port succeeds
- hostname on a different port is denied
- shared IP does not authorize a sibling hostname
- direct IP traffic is denied by default
- direct IP traffic succeeds only with matching `cidr + port`
- TLS SNI match is required by default for endpoint traffic
- per-endpoint SNI disable works only for that endpoint
- `http` without `mitm.required: true` fails validation
- required MITM denies when TLS inspection is unavailable
- endpoint-local HTTP policy allows and denies by method and path
- old network fields fail validation with a migration message

## Non-Goals

- Backward compatibility for old DNS/TCP/TLS config fields
- Header-aware, body-aware, or query-aware HTTP policy
- MITM for direct IP rules
- Preserving top-level HTTP rules
- Per-endpoint custom CA configuration
