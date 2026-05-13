# Endpoint-Scoped Network Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Keel's split DNS/TCP/TLS/MITM/HTTP network config with endpoint-scoped policy where each endpoint states host, port, TLS, MITM, and HTTP access in one reviewable rule.

**Architecture:** Make `internal/network` expose one transport policy module that owns endpoint matching, DNS answer observation, scoped endpoint authorization, direct IP rules, TLS SNI validation, audit conversion, and MITM requirement decisions. Config loading breaks old network fields and maps YAML directly into endpoint and IP rule structures. Proxies become adapters around the policy seam: DNS asks whether to resolve and records answers; TCP asks whether to forward, MITM, or deny.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `github.com/miekg/dns`, existing Keel DNS/TCP/MITM proxy modules.

---

## File Structure

- Modify `internal/config/config.go`
  - Replace old `DNSConfig`, `TCPConfig`, `TLSConfig`, top-level `HTTPConfig`, and old MITM mode fields with `EndpointConfig`, `EndpointTLSConfig`, `EndpointMITMConfig`, `EndpointHTTPConfig`, `EndpointHTTPRuleConfig`, and `IPRuleConfig`.
- Modify `internal/config/defaults.go`
  - Remove defaults for removed fields. Keep top-level MITM CA defaults only.
- Modify `internal/config/loader.go`
  - Update presence tracking for endpoint arrays, IP rule arrays, endpoint-local HTTP fields, and MITM CA flags. Reject old network fields with targeted migration errors.
- Modify `internal/config/loader_test.go`
  - Replace old network merge tests with endpoint/IP/MITM CA tests and old-field rejection tests.
- Modify `internal/network/policy.go`
  - Replace old `PolicyConfig`, `RuleSet`, `CIDRRuleSet`, and `EvaluateDNS`/`EvaluateTCP` model with endpoint-scoped policy methods.
- Modify `internal/network/tracker.go`
  - Replace `ip -> []domain` with active endpoint authorizations scoped by IP, host, port, expiry, SNI requirement, MITM requirement, and endpoint HTTP policy.
- Modify `internal/network/policy_test.go`
  - Replace old tests with endpoint authorization, shared-IP, direct-IP, SNI, audit, and MITM decision tests.
- Modify `internal/network/dns.go`
  - Adapt DNS proxy to call the new policy DNS interface and observe answers with endpoint authorization metadata.
- Modify `internal/network/dns_test.go`
  - Update DNS tests for endpoint match, endpoint miss, scoped authorization recording, and audit logs.
- Modify `internal/network/tcp.go`
  - Adapt TCP proxy to consume the new TCP decision, use endpoint host for summaries, and require MITM when policy says so.
- Modify `internal/network/tcp_test.go`
  - Update TCP tests for endpoint port scoping, SNI matching, direct IP rules, audit, and required MITM failure.
- Modify `internal/cli/host_runner.go`
  - Build new `network.PolicyConfig` from `config.NetworkConfig`, attach endpoint-local HTTP policy to required-MITM decisions, remove top-level HTTP and MITM enabled/bypass wiring.
- Modify `internal/cli/host_runner_test.go`
  - Update service construction and MITM tests for endpoint-local HTTP and required MITM.
- Modify `internal/cli/config.go`
  - Update generated `keel config init` network example.
- Modify `README.md` and `keel.yaml.example`
  - Replace old network examples with endpoint-scoped examples.

---

### Task 1: Replace Config Types And Defaults

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Test: `internal/config/loader_test.go`

- [ ] **Step 1: Write failing config type/default tests**

Replace the network assertions in `TestLoadMergedConfig`, `TestLoadMITMAndHTTPDefaults`, and the MITM/HTTP parse tests with endpoint-scoped expectations. Add this test near the network config tests:

```go
func TestLoadParsesEndpointScopedNetworkPolicy(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mkdirAll(t, filepath.Join(tmpHome, ".config", "keel"))
	writeFile(t, filepath.Join(projectDir, "keel.yaml"), `
network:
  audit: true
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
            paths: ["/repos/*"]
    - host: objects.githubusercontent.com
      port: 443
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
`)

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Network.Audit {
		t.Fatal("network audit should be true")
	}
	if len(cfg.Network.Endpoints) != 2 {
		t.Fatalf("len(endpoints) = %d, want 2", len(cfg.Network.Endpoints))
	}
	ep := cfg.Network.Endpoints[0]
	if ep.Host != "api.github.com" || ep.Port != 443 {
		t.Fatalf("endpoint = %+v, want api.github.com:443", ep)
	}
	if ep.TLS == nil || !ep.TLS.RequireSNIMatch {
		t.Fatalf("endpoint TLS = %+v, want require_sni_match true", ep.TLS)
	}
	if ep.MITM == nil || !ep.MITM.Required {
		t.Fatalf("endpoint MITM = %+v, want required true", ep.MITM)
	}
	if ep.HTTP == nil || ep.HTTP.Default != "deny" || len(ep.HTTP.Rules) != 1 {
		t.Fatalf("endpoint HTTP = %+v, want default deny with one rule", ep.HTTP)
	}
	if ep.HTTP.Rules[0].Action != "allow" || ep.HTTP.Rules[0].Methods[0] != "GET" || ep.HTTP.Rules[0].Paths[0] != "/repos/*" {
		t.Fatalf("endpoint HTTP rule = %+v", ep.HTTP.Rules[0])
	}
	if len(cfg.Network.IPRules) != 1 || cfg.Network.IPRules[0].CIDR != "10.20.0.0/16" || cfg.Network.IPRules[0].Port != 5432 {
		t.Fatalf("ip_rules = %+v", cfg.Network.IPRules)
	}
	if cfg.Network.MITM.CA.Name != "keel-local-ca" || !cfg.Network.MITM.CA.InstallSystem || !cfg.Network.MITM.CA.InstallDocker {
		t.Fatalf("MITM CA = %+v", cfg.Network.MITM.CA)
	}
}
```

- [ ] **Step 2: Verify the test fails**

Run:

```bash
go test ./internal/config -run TestLoadParsesEndpointScopedNetworkPolicy -count=1
```

Expected: FAIL because `NetworkConfig` has no `Endpoints` or `IPRules` fields.

- [ ] **Step 3: Implement config structs and defaults**

Change `internal/config/config.go` network types to:

```go
type NetworkConfig struct {
	Mode      string          `yaml:"mode"`
	Audit     bool            `yaml:"audit"`
	Endpoints []EndpointConfig `yaml:"endpoints"`
	IPRules   []IPRuleConfig  `yaml:"ip_rules"`
	MITM      MITMConfig      `yaml:"mitm"`

	LogDecisions bool `yaml:"-"`
}

type EndpointConfig struct {
	Host string              `yaml:"host"`
	Port int                 `yaml:"port"`
	TLS  *EndpointTLSConfig  `yaml:"tls,omitempty"`
	MITM *EndpointMITMConfig `yaml:"mitm,omitempty"`
	HTTP *EndpointHTTPConfig `yaml:"http,omitempty"`
}

type EndpointTLSConfig struct {
	RequireSNIMatch bool `yaml:"require_sni_match"`
}

type EndpointMITMConfig struct {
	Required bool `yaml:"required"`
}

type EndpointHTTPConfig struct {
	Default string                   `yaml:"default"`
	Rules   []EndpointHTTPRuleConfig `yaml:"rules"`
}

type EndpointHTTPRuleConfig struct {
	Action  string   `yaml:"action"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
}

type IPRuleConfig struct {
	CIDR string `yaml:"cidr"`
	Port int    `yaml:"port"`
}

type MITMConfig struct {
	CA MITMCAConfig `yaml:"ca"`
}
```

Update `internal/config/defaults.go` to remove old DNS/TCP/TLS/HTTP/MITM mode defaults and keep:

```go
Network: NetworkConfig{
	Mode:  "vsock",
	Audit: false,
	MITM: MITMConfig{
		CA: MITMCAConfig{
			Name:          "keel-local-ca",
			InstallSystem: true,
			InstallDocker: true,
		},
	},
},
```

- [ ] **Step 4: Run the focused config test**

Run:

```bash
go test ./internal/config -run TestLoadParsesEndpointScopedNetworkPolicy -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/defaults.go internal/config/loader_test.go
git commit -m "config: add endpoint-scoped network model"
```

---

### Task 2: Break Old Network Config With Targeted Validation

**Files:**
- Modify: `internal/config/loader.go`
- Modify: `internal/config/loader_test.go`

- [ ] **Step 1: Write failing old-field rejection tests**

Add this table test to `internal/config/loader_test.go`:

```go
func TestLoadRejectsOldNetworkPolicyFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "dns", body: "network:\n  dns:\n    allowed: [api.github.com]\n"},
		{name: "tcp", body: "network:\n  tcp:\n    allowed_cidrs: [10.0.0.0/8]\n"},
		{name: "tls", body: "network:\n  tls:\n    allowed_sni: [api.github.com]\n"},
		{name: "deny_if_no_sni", body: "network:\n  deny_if_no_sni: true\n"},
		{name: "top_level_http", body: "network:\n  http:\n    default: deny\n"},
		{name: "mitm_enabled", body: "network:\n  mitm:\n    enabled: true\n"},
		{name: "mitm_bypass", body: "network:\n  mitm:\n    bypass:\n      hosts: [api.github.com]\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpHome := t.TempDir()
			projectDir := t.TempDir()
			t.Setenv("HOME", tmpHome)
			mkdirAll(t, filepath.Join(tmpHome, ".config", "keel"))
			writeFile(t, filepath.Join(projectDir, "keel.yaml"), tt.body)

			_, err := Load(LoadOptions{WorkingDir: projectDir})
			if err == nil {
				t.Fatal("Load() error = nil, want old network field rejection")
			}
			if !strings.Contains(err.Error(), "network.endpoints") || !strings.Contains(err.Error(), "network.ip_rules") {
				t.Fatalf("Load() error = %v, want migration guidance", err)
			}
		})
	}
}
```

- [ ] **Step 2: Verify the test fails**

Run:

```bash
go test ./internal/config -run TestLoadRejectsOldNetworkPolicyFields -count=1
```

Expected: FAIL because old fields are ignored or parsed into removed structs rather than rejected.

- [ ] **Step 3: Implement old-field detection and endpoint validation**

In `internal/config/loader.go`, replace old presence structs with:

```go
type mergePresenceConfig struct {
	Workspace mergePresenceWorkspaceConfig `yaml:"workspace"`
	Network   mergePresenceNetworkConfig   `yaml:"network"`
	Process   *mergePresenceProcessConfig  `yaml:"process"`
}

type mergePresenceNetworkConfig struct {
	Audit     *bool                    `yaml:"audit"`
	Endpoints *[]EndpointConfig        `yaml:"endpoints"`
	IPRules   *[]IPRuleConfig         `yaml:"ip_rules"`
	MITM      *mergePresenceMITMConfig `yaml:"mitm"`

	OldDenyIfNoSNI *bool        `yaml:"deny_if_no_sni"`
	OldDNS         any          `yaml:"dns"`
	OldTCP         any          `yaml:"tcp"`
	OldTLS         any          `yaml:"tls"`
	OldHTTP        any          `yaml:"http"`
}

type mergePresenceMITMConfig struct {
	CA *mergePresenceMITMCA `yaml:"ca"`

	OldEnabled         *bool   `yaml:"enabled"`
	OldMode            *string `yaml:"mode"`
	OldOnUntrustedCert *string `yaml:"on_untrusted_cert"`
	OldLogRequests     *bool   `yaml:"log_requests"`
	OldBypass          any     `yaml:"bypass"`
}
```

Add a helper:

```go
func rejectOldNetworkFields(p mergePresenceNetworkConfig) error {
	if p.OldDenyIfNoSNI != nil || p.OldDNS != nil || p.OldTCP != nil || p.OldTLS != nil || p.OldHTTP != nil {
		return errors.New("old network policy fields were removed; migrate to network.endpoints and network.ip_rules")
	}
	if p.MITM != nil && (p.MITM.OldEnabled != nil || p.MITM.OldMode != nil || p.MITM.OldOnUntrustedCert != nil || p.MITM.OldLogRequests != nil || p.MITM.OldBypass != nil) {
		return errors.New("old network MITM fields were removed; migrate policy decisions to network.endpoints[].mitm and direct IP access to network.ip_rules")
	}
	return nil
}
```

Call it from `mergeConfigFile` after unmarshalling `presenceCfg`.

Update `mergeConfig` to replace `Endpoints` and `IPRules` when present:

```go
if presence.Network.Endpoints != nil {
	dst.Network.Endpoints = append([]EndpointConfig(nil), src.Network.Endpoints...)
}
if presence.Network.IPRules != nil {
	dst.Network.IPRules = append([]IPRuleConfig(nil), src.Network.IPRules...)
}
```

Update `validateConfig` to call `validateNetwork(cfg.Network)` and implement:

```go
func validateNetwork(network NetworkConfig) error {
	for _, endpoint := range network.Endpoints {
		if strings.TrimSpace(endpoint.Host) == "" {
			return errors.New("network.endpoints.host is required")
		}
		if endpoint.Port <= 0 || endpoint.Port > 65535 {
			return errors.New("network.endpoints.port must be between 1 and 65535")
		}
		mitmRequired := endpoint.MITM != nil && endpoint.MITM.Required
		if endpoint.HTTP != nil && !mitmRequired {
			return errors.New("network.endpoints.http requires network.endpoints.mitm.required")
		}
		if endpoint.HTTP != nil {
			if err := validateEndpointHTTP(*endpoint.HTTP); err != nil {
				return err
			}
		}
	}
	for _, rule := range network.IPRules {
		if strings.TrimSpace(rule.CIDR) == "" {
			return errors.New("network.ip_rules.cidr is required")
		}
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return errors.New("network.ip_rules.cidr must be a valid CIDR")
		}
		if rule.Port <= 0 || rule.Port > 65535 {
			return errors.New("network.ip_rules.port must be between 1 and 65535")
		}
	}
	return nil
}
```

Add `net` to imports.

- [ ] **Step 4: Run config tests**

Run:

```bash
go test ./internal/config -count=1
```

Expected: PASS after updating old tests that asserted removed fields.

- [ ] **Step 5: Commit**

```bash
git add internal/config/loader.go internal/config/loader_test.go
git commit -m "config: reject legacy network policy fields"
```

---

### Task 3: Deepen Network Policy Around Endpoint Authorizations

**Files:**
- Modify: `internal/network/policy.go`
- Modify: `internal/network/tracker.go`
- Modify: `internal/network/policy_test.go`

- [ ] **Step 1: Write failing endpoint policy tests**

Replace old `TestPolicyAllowsDNSAndCorrelatedTLS` with:

```go
func TestPolicyAuthorizesEndpointByHostPortAndSNI(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "api.github.com",
			Port:            443,
			RequireSNIMatch: true,
		}},
	}, NewTracker(60*time.Second))

	dnsDecision, authorizations := policy.EvaluateDNS("api.github.com")
	if !dnsDecision.Allowed || len(authorizations) != 1 {
		t.Fatalf("EvaluateDNS() = %+v, authorizations=%+v", dnsDecision, authorizations)
	}
	policy.ObserveDNS("api.github.com", []net.IP{net.ParseIP("140.82.112.6")}, 30*time.Second, time.Unix(100, 0), authorizations)

	decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "api.github.com", true, time.Unix(110, 0))
	if !decision.Allowed {
		t.Fatalf("EvaluateTCP() denied: %+v", decision)
	}
	if decision.EndpointHost != "api.github.com" || decision.Rule != "endpoint:api.github.com:443" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestPolicyDoesNotReuseEndpointAuthorizationAcrossPortsOrSiblingHosts(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "api.github.com",
			Port:            443,
			RequireSNIMatch: true,
		}},
	}, NewTracker(60*time.Second))
	dnsDecision, authorizations := policy.EvaluateDNS("api.github.com")
	if !dnsDecision.Allowed {
		t.Fatalf("EvaluateDNS() denied: %+v", dnsDecision)
	}
	policy.ObserveDNS("api.github.com", []net.IP{net.ParseIP("140.82.112.6")}, 30*time.Second, time.Unix(100, 0), authorizations)

	if decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 80, "", false, time.Unix(110, 0)); decision.Allowed {
		t.Fatalf("port 80 decision allowed: %+v", decision)
	}
	if decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "gist.github.com", true, time.Unix(110, 0)); decision.Allowed {
		t.Fatalf("sibling host decision allowed: %+v", decision)
	}
}

func TestPolicyAllowsDirectIPOnlyByCIDRAndPort(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		IPRules: []IPRule{{CIDR: "10.20.0.0/16", Port: 5432}},
	}, NewTracker(60*time.Second))

	allowed := policy.EvaluateTCP(net.ParseIP("10.20.1.5"), 5432, "", false, time.Unix(110, 0))
	if !allowed.Allowed || allowed.Rule != "ip:10.20.0.0/16:5432" {
		t.Fatalf("direct IP decision = %+v", allowed)
	}
	if denied := policy.EvaluateTCP(net.ParseIP("10.20.1.5"), 443, "", false, time.Unix(110, 0)); denied.Allowed {
		t.Fatalf("wrong port allowed: %+v", denied)
	}
}
```

- [ ] **Step 2: Verify tests fail**

Run:

```bash
go test ./internal/network -run 'TestPolicyAuthorizesEndpoint|TestPolicyDoesNotReuseEndpoint|TestPolicyAllowsDirectIP' -count=1
```

Expected: FAIL because the new `PolicyConfig`, `EndpointRule`, `IPRule`, `EvaluateDNS` return values, and `ObserveDNS` do not exist yet.

- [ ] **Step 3: Implement endpoint policy types**

In `internal/network/policy.go`, replace old policy structs with:

```go
type PolicyConfig struct {
	Audit     bool
	Endpoints []EndpointRule
	IPRules   []IPRule
}

type EndpointRule struct {
	Host            string
	Port            int
	RequireSNIMatch bool
	MITMRequired    bool
	HTTP            HTTPPolicyConfig
}

type IPRule struct {
	CIDR string
	Port int
}

type DNSAuthorization struct {
	Host            string
	Port            int
	RequireSNIMatch bool
	MITMRequired    bool
	HTTP            HTTPPolicyConfig
	Rule            string
}

type Decision struct {
	Allowed      bool
	WouldDeny    bool
	Reason       string
	Rule         string
	EndpointHost string
	MITMRequired bool
	HTTP         HTTPPolicyConfig
}
```

Implement:

```go
func (e *PolicyEngine) EvaluateDNS(domain string) (Decision, []DNSAuthorization)
func (e *PolicyEngine) ObserveDNS(domain string, ips []net.IP, ttl time.Duration, now time.Time, auths []DNSAuthorization)
func (e *PolicyEngine) EvaluateTCP(ip net.IP, port int, sni string, isTLS bool, now time.Time) Decision
```

Rules:

- `EvaluateDNS` matches `domain` against `EndpointRule.Host` and returns one authorization per matching endpoint.
- No endpoint match denies with reason `host not covered by endpoint`.
- `ObserveDNS` stores the returned authorizations for each answer IP.
- `EvaluateTCP` first asks the tracker for authorizations matching `ip + port`.
- If an endpoint authorization exists and SNI is required for TLS, require normalized SNI equals authorization host.
- If no endpoint authorization exists, check `IPRules` by CIDR and port.
- Audit conversion remains in `applyAudit`.

- [ ] **Step 4: Replace tracker state**

In `internal/network/tracker.go`, replace `trackedDomain` with:

```go
type trackedAuthorization struct {
	authorization DNSAuthorization
	expiresAt     time.Time
}
```

Store by IP string as before, but expose:

```go
func (t *Tracker) ObserveAuthorization(ip net.IP, ttl time.Duration, now time.Time, authorization DNSAuthorization)
func (t *Tracker) Authorizations(ip net.IP, port int, now time.Time) []DNSAuthorization
func (t *Tracker) Host(ip net.IP, port int, now time.Time) string
```

Keep expiry cleanup inside `Authorizations`.

- [ ] **Step 5: Run policy tests**

Run:

```bash
go test ./internal/network -run 'TestPolicy|TestSummaryLabelsWouldDeny' -count=1
```

Expected: PASS after replacing old policy tests.

- [ ] **Step 6: Commit**

```bash
git add internal/network/policy.go internal/network/tracker.go internal/network/policy_test.go
git commit -m "network: authorize egress by endpoint and port"
```

---

### Task 4: Adapt DNS Proxy To Endpoint Authorization

**Files:**
- Modify: `internal/network/dns.go`
- Modify: `internal/network/dns_test.go`

- [ ] **Step 1: Write failing DNS proxy tests**

Update `TestDNSProxyAllowsAndTracksAnswers` to configure endpoint policy:

```go
engine := NewPolicyEngine(PolicyConfig{
	Endpoints: []EndpointRule{{Host: "*.github.com", Port: 443, RequireSNIMatch: true}},
}, tracker)
```

Replace the tracker assertion with:

```go
auths := tracker.Authorizations(net.ParseIP("140.82.112.6"), 443, time.Unix(110, 0))
if len(auths) != 1 || auths[0].Host != "api.github.com" || auths[0].Port != 443 {
	t.Fatalf("tracked authorizations = %#v", auths)
}
```

Update `TestDNSProxyDeniesBlockedDomain` into `TestDNSProxyDeniesDomainWithoutEndpoint` with no matching endpoint and assert summary contains:

```go
assertSummaryReportContains(t, summary, "dns  gist.github.com:53 policy=denied count=1")
```

- [ ] **Step 2: Verify DNS tests fail**

Run:

```bash
go test ./internal/network -run 'TestDNSProxyAllowsAndTracksAnswers|TestDNSProxyDeniesDomainWithoutEndpoint' -count=1
```

Expected: FAIL because `DNSProxy.HandleQuery` still expects `EvaluateDNS` to return only a `Decision` and still calls `Tracker.Observe`.

- [ ] **Step 3: Update DNS proxy implementation**

In `HandleQuery`, change:

```go
decision := p.Policy.EvaluateDNS(query.Question[0].Name)
```

to:

```go
decision, authorizations := p.Policy.EvaluateDNS(query.Question[0].Name)
```

Change `observeAnswers` signature to:

```go
func (p DNSProxy) observeAnswers(domain string, reply *dns.Msg, now time.Time, authorizations []DNSAuthorization)
```

Collect A/AAAA IPs and call:

```go
p.Policy.ObserveDNS(domain, ips, time.Duration(rr.Hdr.Ttl)*time.Second, now, authorizations)
```

Use the lowest TTL among returned records or call once per record with its TTL.

- [ ] **Step 4: Run DNS tests**

Run:

```bash
go test ./internal/network -run 'TestDNSProxy|TestPolicy' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/network/dns.go internal/network/dns_test.go
git commit -m "network: track endpoint authorizations from dns"
```

---

### Task 5: Adapt TCP Proxy And Required MITM Decisions

**Files:**
- Modify: `internal/network/tcp.go`
- Modify: `internal/network/tcp_test.go`

- [ ] **Step 1: Write failing TCP endpoint and MITM tests**

Update `TestTCPProxyAllowsCorrelatedDestination` to record endpoint authorization through policy:

```go
engine := NewPolicyEngine(PolicyConfig{
	Endpoints: []EndpointRule{{Host: "api.github.com", Port: 80}},
}, tracker)
_, auths := engine.EvaluateDNS("api.github.com")
engine.ObserveDNS("api.github.com", []net.IP{net.ParseIP("203.0.113.10")}, 30*time.Second, time.Unix(100, 0), auths)
```

Add:

```go
func TestTCPProxyDeniesRequiredMITMWhenClientHelloCannotBeParsed(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:         "api.github.com",
			Port:         443,
			MITMRequired: true,
		}},
	}, tracker)
	_, auths := engine.EvaluateDNS("api.github.com")
	engine.ObserveDNS("api.github.com", []net.IP{net.ParseIP("203.0.113.10")}, 30*time.Second, time.Unix(100, 0), auths)

	summary := NewSummary()
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	var dialed bool
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now:     func() time.Time { return time.Unix(110, 0) },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, fmt.Errorf("unexpected dial")
		},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- proxy.handleConn(context.Background(), proxySide) }()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write([]byte("not tls")); err != nil {
		t.Fatalf("client write error = %v", err)
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
	if dialed {
		t.Fatal("dialer was called for required MITM without TLS inspection")
	}
	assertSummaryReportContains(t, summary, "tcp  api.github.com:443 policy=denied count=1")
}
```

- [ ] **Step 2: Verify TCP tests fail**

Run:

```bash
go test ./internal/network -run 'TestTCPProxyAllowsCorrelatedDestination|TestTCPProxyDeniesRequiredMITMWhenClientHelloCannotBeParsed' -count=1
```

Expected: FAIL until TCP proxy reads `Decision.MITMRequired` and summary host from `Decision.EndpointHost`.

- [ ] **Step 3: Update TCP proxy decision handling**

In `handleConn`, after:

```go
decision := p.Policy.EvaluateTCP(ip, port, sni, isTLS, now)
```

replace MITM parsing behavior with:

```go
if decision.Allowed && decision.MITMRequired {
	if !isTLS || tlsInspectionRequired(preface, sni, inspectErr) || p.MITM == nil || !p.MITM.Enabled {
		decision = Decision{Reason: "required mitm inspection unavailable", Rule: decision.Rule, EndpointHost: decision.EndpointHost}
	}
}
```

Use endpoint host for summaries:

```go
p.Summary.RecordTCP(summaryHostForDecision(p.Policy, decision, ip, sni, now), port, decision)
```

Implement:

```go
func summaryHostForDecision(policy *PolicyEngine, decision Decision, ip net.IP, sni string, now time.Time) string {
	if decision.EndpointHost != "" {
		return decision.EndpointHost
	}
	return summaryHost(policy, ip, sni, now)
}
```

When handling TLS MITM, require `decision.MITMRequired` instead of top-level MITM enablement alone for required inspection:

```go
if decision.MITMRequired && isTLS && len(preface) > 0 && sni != "" {
	return p.MITM.HandleTLS(ctx, &prefixedConn{Conn: conn, prefix: bytes.NewReader(preface)}, sni, destination)
}
```

Keep optional plaintext HTTP MITM only if an endpoint decision carries HTTP policy and MITM is configured.

- [ ] **Step 4: Run TCP tests**

Run:

```bash
go test ./internal/network -run 'TestTCPProxy|TestPolicy|TestDNSProxy' -count=1
```

Expected: PASS after updating old TCP tests for endpoint policy setup.

- [ ] **Step 5: Commit**

```bash
git add internal/network/tcp.go internal/network/tcp_test.go
git commit -m "network: enforce required mitm from endpoint policy"
```

---

### Task 6: Wire CLI Service Construction To New Policy

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`

- [ ] **Step 1: Write failing host runner service tests**

Update the existing `buildNetworkServices` tests around MITM and HTTP to configure endpoint-local policy:

```go
cfg.Network.Endpoints = []config.EndpointConfig{{
	Host: "api.github.com",
	Port: 443,
	TLS:  &config.EndpointTLSConfig{RequireSNIMatch: true},
	MITM: &config.EndpointMITMConfig{Required: true},
	HTTP: &config.EndpointHTTPConfig{
		Default: "deny",
		Rules: []config.EndpointHTTPRuleConfig{{
			Action:  "allow",
			Methods: []string{"GET"},
			Paths:   []string{"/repos/*"},
		}},
	},
}}
```

Assert:

```go
if tcpProxy.MITM == nil {
	t.Fatal("TCP proxy MITM = nil, want configured when endpoint requires MITM")
}
decision, auths := dnsProxy.Policy.EvaluateDNS("api.github.com")
if !decision.Allowed || len(auths) != 1 || !auths[0].MITMRequired {
	t.Fatalf("endpoint auth = decision %+v auths %+v", decision, auths)
}
```

- [ ] **Step 2: Verify host runner tests fail**

Run:

```bash
go test ./internal/cli -run 'TestHostRunner.*MITM|TestHostRunner.*Network|TestHostRunnerStartServicesStartsDNSAndTCPProxies' -count=1
```

Expected: FAIL because `buildNetworkServices` still maps old config fields.

- [ ] **Step 3: Implement config-to-policy mapping**

In `internal/cli/host_runner.go`, replace `buildNetworkServices` mapping with:

```go
policyCfg := network.PolicyConfig{
	Audit:     cfg.Network.Audit,
	Endpoints: endpointRulesFromConfig(cfg.Network.Endpoints),
	IPRules:   ipRulesFromConfig(cfg.Network.IPRules),
}
engine := network.NewPolicyEngine(policyCfg, tracker)
```

Add:

```go
func endpointRulesFromConfig(items []config.EndpointConfig) []network.EndpointRule {
	rules := make([]network.EndpointRule, 0, len(items))
	for _, item := range items {
		rule := network.EndpointRule{
			Host: item.Host,
			Port: item.Port,
			RequireSNIMatch: true,
		}
		if item.TLS != nil {
			rule.RequireSNIMatch = item.TLS.RequireSNIMatch
		}
		if item.MITM != nil {
			rule.MITMRequired = item.MITM.Required
		}
		if item.HTTP != nil {
			rule.HTTP = endpointHTTPPolicyFromConfig(*item.HTTP)
		}
		rules = append(rules, rule)
	}
	return rules
}

func endpointHTTPPolicyFromConfig(item config.EndpointHTTPConfig) network.HTTPPolicyConfig {
	return network.HTTPPolicyConfig{
		Default: item.Default,
		Rules:   endpointHTTPRulesFromConfig(item.Rules),
	}
}

func endpointHTTPRulesFromConfig(items []config.EndpointHTTPRuleConfig) []network.HTTPRule {
	rules := make([]network.HTTPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.HTTPRule{
			Action:  item.Action,
			Methods: append([]string(nil), item.Methods...),
			Paths:   append([]string(nil), item.Paths...),
		})
	}
	return rules
}

func ipRulesFromConfig(items []config.IPRuleConfig) []network.IPRule {
	rules := make([]network.IPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.IPRule{CIDR: item.CIDR, Port: item.Port})
	}
	return rules
}
```

Create `tcpProxy.MITM` when any endpoint rule requires MITM:

```go
if policyRequiresMITM(policyCfg) {
	ca, err := loadMITMCA(cfg)
	if err != nil {
		return network.DNSProxy{}, network.TCPProxy{}, nil, err
	}
	tcpProxy.MITM = &network.MITMProxy{
		Enabled: true,
		CA:      ca,
		Summary: summary,
	}
}
```

Remove top-level HTTP policy and bypass wiring.

- [ ] **Step 4: Run CLI tests**

Run:

```bash
go test ./internal/cli -count=1
```

Expected: PASS after updating old tests.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go
git commit -m "cli: wire endpoint scoped network policy"
```

---

### Task 7: Update User-Facing Config And Docs

**Files:**
- Modify: `internal/cli/config.go`
- Modify: `README.md`
- Modify: `keel.yaml.example`

- [ ] **Step 1: Update docs and init template**

Replace old network examples with:

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
    - host: auth.docker.io
      port: 443
      tls:
        require_sni_match: true
  ip_rules: []
  mitm:
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true
```

Update prose to say:

- endpoint rules are the primary review surface
- HTTP policy lives under endpoints and requires `mitm.required: true`
- direct IP rules cannot define MITM or HTTP policy
- old DNS/TCP/TLS fields are removed

- [ ] **Step 2: Run doc/config checks**

Run:

```bash
go test ./internal/cli -run TestConfig -count=1
rg -n "deny_if_no_sni|network\\.dns|allowed_sni|allowed_cidrs|mitm:\\n    enabled|network:\\n  http" README.md keel.yaml.example internal/cli/config.go
```

Expected: tests PASS; `rg` finds no old network config examples.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/config.go README.md keel.yaml.example
git commit -m "docs: document endpoint scoped network config"
```

---

### Task 8: Full Verification

**Files:**
- No source changes expected.

- [ ] **Step 1: Run all Go tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 2: Run guest Go tests**

Run:

```bash
(cd guest && go test ./...)
```

Expected: PASS.

- [ ] **Step 3: Search for removed config fields**

Run:

```bash
rg -n "DenyIfNoSNI|DNSConfig|TCPConfig|TLSConfig|HTTPConfig|AllowedSNI|DeniedSNI|AllowedCIDRs|DeniedCIDRs|network\\.dns|deny_if_no_sni|allowed_sni|allowed_cidrs|mitm\\.enabled|MITM\\.Enabled" .
```

Expected: no production references to removed config fields. Historical design docs may still mention old fields only when explicitly describing the removed model.

- [ ] **Step 4: Final commit if needed**

If verification required any fixes:

```bash
git add .
git commit -m "test: verify endpoint scoped network policy"
```

---

## Self-Review

### Spec Coverage

- Endpoint-scoped config is covered in Tasks 1, 2, 6, and 7.
- Breaking old config compatibility is covered in Task 2.
- Scoped DNS authorization and shared-IP behavior are covered in Tasks 3 and 4.
- TCP port scoping, direct IP rules, SNI validation, audit conversion, and required MITM are covered in Tasks 3 and 5.
- Endpoint-local HTTP policy is covered in Tasks 1, 5, and 6.
- Documentation updates are covered in Task 7.

### Placeholder Scan

No `TODO`, `TBD`, or placeholder implementation steps remain.

### Type Consistency

The plan consistently uses:

- `config.EndpointConfig` and `network.EndpointRule`
- `config.IPRuleConfig` and `network.IPRule`
- `EndpointHTTPConfig` / `EndpointHTTPRuleConfig`
- `EndpointTLSConfig.RequireSNIMatch`
- `EndpointMITMConfig.Required`
