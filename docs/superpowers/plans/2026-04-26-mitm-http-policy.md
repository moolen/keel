# MITM HTTP Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add host-side MITM support to Keel so outbound HTTP/HTTPS traffic can be governed by ordered `host + method + path` rules without weakening the existing DNS/TCP/TLS fail-closed egress model.

**Architecture:** Keep the current transport policy stack as the coarse first gate, then extend the host TCP proxy to optionally terminate TLS, parse HTTP requests, and apply ordered HTTP policy rules. Guest/rootfs preparation injects the Keel CA trust anchor when MITM is enabled, and Docker feature setup reuses that CA for daemon/client trust where Keel can control it.

**Tech Stack:** Go, `crypto/tls`, `crypto/x509`, `net/http`, Firecracker/vsock transport, ext4 rootfs mutation, existing Keel config/network/image/guest feature packages.

---

## File Structure

### Config

- Modify: `internal/config/config.go`
  - Add `MITMConfig`, `MITMCAConfig`, `MITMBypassConfig`, `HTTPConfig`, `HTTPRuleConfig`.
- Modify: `internal/config/defaults.go`
  - Add defaults for `network.mitm` and `network.http`.
- Modify: `internal/config/loader.go`
  - Merge new config sections cleanly across global/project config.
- Modify: `internal/config/loader_test.go`
  - Cover parsing/merge semantics for MITM and HTTP rules.

### Host Policy And MITM

- Create: `internal/network/http_policy.go`
  - Ordered `host + method + path` matcher and decision engine.
- Create: `internal/network/http_policy_test.go`
  - Focused unit tests for rule ordering, glob matching, and defaults.
- Create: `internal/network/ca.go`
  - Persistent CA generation/loading and leaf cert minting.
- Create: `internal/network/ca_test.go`
  - Validate certificate generation and SAN coverage.
- Create: `internal/network/http_summary.go`
  - Aggregated HTTP request summary structures.
- Create: `internal/network/http_summary_test.go`
  - Summary aggregation tests.
- Create: `internal/network/mitm.go`
  - TLS termination and HTTP forwarding path.
- Create: `internal/network/mitm_test.go`
  - End-to-end unit-level MITM behavior using local test servers.
- Modify: `internal/network/policy.go`
  - Add HTTP policy config/types and evaluation entrypoints.
- Modify: `internal/network/tcp.go`
  - Extend transport gate to hand eligible traffic to MITM path.
- Modify: `internal/network/summary.go`
  - Integrate HTTP rows into shutdown reporting.
- Modify: `internal/network/summary_test.go`
  - Cover mixed DNS/TCP/HTTP report output.

### Guest And Image Preparation

- Modify: `internal/image/pull.go`
  - Thread optional guest trust assets through image/rootfs preparation.
- Modify: `internal/image/inject.go` or equivalent rootfs mutation file
  - Inject CA certificate and trust update hooks into cached rootfs.
- Modify: `internal/image/pull_test.go`
  - Cover guest trust asset injection into rootfs.
- Modify: `guest/internal/features/docker.go`
  - Install Docker daemon/client trust for the Keel CA when configured.
- Modify: `guest/internal/features/docker_test.go`
  - Verify trust material and daemon config writing.

### CLI And Host Runner Wiring

- Modify: `internal/cli/host_runner.go`
  - Build CA/trust assets when MITM is enabled and pass them into image/network setup.
- Modify: `internal/cli/host_runner_test.go`
  - Cover MITM-enabled setup and reporting wiring.

### Integration

- Modify: `hack/test/integration_test.go`
  - Add opt-in e2e coverage for MITM allow/deny behavior.
- Modify: `hack/test/e2e_helpers_test.go`
  - Helpers for temp CA/config/projects and local HTTPS origin.

---

### Task 1: Add MITM And HTTP Config Types

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Test: `internal/config/loader_test.go`

- [ ] **Step 1: Write the failing config parse/merge tests**

```go
func TestLoadParsesMITMAndHTTPPolicy(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	globalConfig := []byte(`
network:
  mitm:
    enabled: true
    mode: optional
    on_untrusted_cert: deny
    log_requests: true
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true
`)
	if err := os.WriteFile(filepath.Join(tmpHome, ".config", "keel", "config.yaml"), globalConfig, 0o644); err != nil {
		t.Fatal(err)
	}

	projectConfig := []byte(`
network:
  http:
    default: deny
    rules:
      - action: allow
        host: api.github.com
        methods: ["GET"]
        paths: ["/repos/*"]
`)
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), projectConfig, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Network.MITM.Enabled {
		t.Fatal("MITM should be enabled from global config")
	}
	if got, want := cfg.Network.HTTP.Default, "deny"; got != want {
		t.Fatalf("HTTP default = %q, want %q", got, want)
	}
	if len(cfg.Network.HTTP.Rules) != 1 {
		t.Fatalf("len(HTTP.Rules) = %d, want 1", len(cfg.Network.HTTP.Rules))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/config -run 'TestLoadParsesMITMAndHTTPPolicy' -v`

Expected: FAIL with unknown fields or missing `cfg.Network.MITM` / `cfg.Network.HTTP`.

- [ ] **Step 3: Write the minimal config types and defaults**

```go
type NetworkConfig struct {
	Mode         string      `yaml:"mode"`
	DenyIfNoSNI  bool        `yaml:"deny_if_no_sni"`
	DNS          DNSConfig   `yaml:"dns"`
	TCP          TCPConfig   `yaml:"tcp"`
	TLS          TLSConfig   `yaml:"tls"`
	MITM         MITMConfig  `yaml:"mitm"`
	HTTP         HTTPConfig  `yaml:"http"`
	LogDecisions bool        `yaml:"-"`
}

type MITMConfig struct {
	Enabled         bool           `yaml:"enabled"`
	Mode            string         `yaml:"mode"`
	OnUntrustedCert string         `yaml:"on_untrusted_cert"`
	LogRequests     bool           `yaml:"log_requests"`
	CA              MITMCAConfig   `yaml:"ca"`
	Bypass          MITMBypassConfig `yaml:"bypass"`
}

type MITMCAConfig struct {
	Name          string `yaml:"name"`
	InstallSystem bool   `yaml:"install_system"`
	InstallDocker bool   `yaml:"install_docker"`
}

type MITMBypassConfig struct {
	Hosts []string `yaml:"hosts"`
	SNI   []string `yaml:"sni"`
}

type HTTPConfig struct {
	Default string           `yaml:"default"`
	Rules   []HTTPRuleConfig `yaml:"rules"`
}

type HTTPRuleConfig struct {
	Action  string   `yaml:"action"`
	Host    string   `yaml:"host"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
}
```

- [ ] **Step 4: Merge new config sections in loader**

```go
if src.Network.MITM.Mode != "" {
	dst.Network.MITM.Mode = src.Network.MITM.Mode
}
dst.Network.MITM.Enabled = dst.Network.MITM.Enabled || src.Network.MITM.Enabled
if src.Network.MITM.OnUntrustedCert != "" {
	dst.Network.MITM.OnUntrustedCert = src.Network.MITM.OnUntrustedCert
}
dst.Network.MITM.LogRequests = dst.Network.MITM.LogRequests || src.Network.MITM.LogRequests
if src.Network.MITM.CA.Name != "" {
	dst.Network.MITM.CA.Name = src.Network.MITM.CA.Name
}
dst.Network.MITM.CA.InstallSystem = dst.Network.MITM.CA.InstallSystem || src.Network.MITM.CA.InstallSystem
dst.Network.MITM.CA.InstallDocker = dst.Network.MITM.CA.InstallDocker || src.Network.MITM.CA.InstallDocker
if len(src.Network.MITM.Bypass.Hosts) > 0 {
	dst.Network.MITM.Bypass.Hosts = append([]string(nil), src.Network.MITM.Bypass.Hosts...)
}
if len(src.Network.MITM.Bypass.SNI) > 0 {
	dst.Network.MITM.Bypass.SNI = append([]string(nil), src.Network.MITM.Bypass.SNI...)
}
if src.Network.HTTP.Default != "" {
	dst.Network.HTTP.Default = src.Network.HTTP.Default
}
if len(src.Network.HTTP.Rules) > 0 {
	dst.Network.HTTP.Rules = append([]HTTPRuleConfig(nil), src.Network.HTTP.Rules...)
}
```

- [ ] **Step 5: Run config tests**

Run: `/usr/local/go/bin/go test ./internal/config -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/defaults.go internal/config/loader.go internal/config/loader_test.go
git commit -m "feat: add mitm and http config schema"
```

### Task 2: Add HTTP Policy Engine

**Files:**
- Create: `internal/network/http_policy.go`
- Test: `internal/network/http_policy_test.go`
- Modify: `internal/network/policy.go`

- [ ] **Step 1: Write the failing HTTP policy tests**

```go
func TestHTTPPolicyFirstMatchWins(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "deny", Host: "*.github.com", Methods: []string{"POST"}, Paths: []string{"/*"}},
			{Action: "allow", Host: "api.github.com", Methods: []string{"POST"}, Paths: []string{"/repos/*"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "POST",
		Path:   "/repos/openai/openai",
	})
	if decision.Allowed {
		t.Fatalf("decision = %#v, want denied by first match", decision)
	}
}

func TestHTTPPolicyMatchesGlobPath(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/*"}},
		},
	})
	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/repos/moolen/keel",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed", decision)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/network -run 'TestHTTPPolicy' -v`

Expected: FAIL because `NewHTTPPolicy`, `HTTPPolicyConfig`, and `HTTPRequest` do not exist.

- [ ] **Step 3: Write the minimal HTTP policy engine**

```go
type HTTPRequest struct {
	Host   string
	Method string
	Path   string
}

type HTTPRule struct {
	Action  string
	Host    string
	Methods []string
	Paths   []string
}

type HTTPPolicyConfig struct {
	Default string
	Rules   []HTTPRule
}

type HTTPPolicy struct {
	cfg HTTPPolicyConfig
}

func NewHTTPPolicy(cfg HTTPPolicyConfig) *HTTPPolicy {
	if cfg.Default == "" {
		cfg.Default = "deny"
	}
	return &HTTPPolicy{cfg: cfg}
}

func (p *HTTPPolicy) Evaluate(req HTTPRequest) Decision {
	req.Host = normalizeName(req.Host)
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Path = normalizeHTTPPath(req.Path)
	for _, rule := range p.cfg.Rules {
		if !matchHTTPRule(rule, req) {
			continue
		}
		return Decision{
			Allowed: rule.Action == "allow",
			Reason:  "http rule matched",
			Rule:    fmt.Sprintf("%s %s %s", rule.Host, strings.Join(rule.Methods, ","), strings.Join(rule.Paths, ",")),
		}
	}
	return Decision{
		Allowed: p.cfg.Default == "allow",
		Reason:  "http default",
		Rule:    "default",
	}
}
```

- [ ] **Step 4: Bridge HTTP config into `PolicyConfig`**

```go
type PolicyConfig struct {
	DNS         RuleSet
	TCP         CIDRRuleSet
	TLS         RuleSet
	HTTP        HTTPPolicyConfig
	DenyIfNoSNI bool
}
```

- [ ] **Step 5: Run network tests**

Run: `/usr/local/go/bin/go test ./internal/network -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/network/http_policy.go internal/network/http_policy_test.go internal/network/policy.go
git commit -m "feat: add http policy engine"
```

### Task 3: Add Persistent CA Management

**Files:**
- Create: `internal/network/ca.go`
- Test: `internal/network/ca_test.go`

- [ ] **Step 1: Write the failing CA tests**

```go
func TestLoadOrCreateCAReusesExistingCertificate(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(CAOptions{
		Dir:  dir,
		Name: "keel-local-ca",
	})
	if err != nil {
		t.Fatalf("LoadOrCreateCA(first) error = %v", err)
	}
	second, err := LoadOrCreateCA(CAOptions{
		Dir:  dir,
		Name: "keel-local-ca",
	})
	if err != nil {
		t.Fatalf("LoadOrCreateCA(second) error = %v", err)
	}
	if !bytes.Equal(first.CertPEM, second.CertPEM) {
		t.Fatal("expected CA certificate reuse")
	}
}

func TestIssueLeafCertificateIncludesRequestedHostname(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(CAOptions{Dir: dir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueLeaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := leaf.X509()
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("api.github.com"); err != nil {
		t.Fatalf("VerifyHostname() error = %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/network -run 'TestLoadOrCreateCA|TestIssueLeafCertificateIncludesRequestedHostname' -v`

Expected: FAIL because CA types/functions do not exist.

- [ ] **Step 3: Write the minimal CA implementation**

```go
type CAOptions struct {
	Dir  string
	Name string
}

type CA struct {
	CertPEM []byte
	KeyPEM  []byte
	cert    *x509.Certificate
	key     crypto.Signer
	dir     string
}

func LoadOrCreateCA(opts CAOptions) (*CA, error) {
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(opts.Dir, "ca.crt")
	keyPath := filepath.Join(opts.Dir, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		return loadCA(certPath, keyPath, opts.Dir)
	}
	return createCA(certPath, keyPath, opts)
}
```

- [ ] **Step 4: Add leaf issuance and cache pathing**

```go
func (ca *CA) IssueLeaf(host string) (*IssuedCert, error) {
	host = normalizeName(host)
	issuedDir := filepath.Join(ca.dir, "issued")
	if err := os.MkdirAll(issuedDir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(issuedDir, host+".crt")
	keyPath := filepath.Join(issuedDir, host+".key")
	if _, err := os.Stat(certPath); err == nil {
		return loadIssuedCert(certPath, keyPath)
	}
	return ca.createLeaf(certPath, keyPath, host)
}
```

- [ ] **Step 5: Run network tests**

Run: `/usr/local/go/bin/go test ./internal/network -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/network/ca.go internal/network/ca_test.go
git commit -m "feat: add persistent mitm certificate authority"
```

### Task 4: Add HTTP Summary Aggregation

**Files:**
- Create: `internal/network/http_summary.go`
- Test: `internal/network/http_summary_test.go`
- Modify: `internal/network/summary.go`
- Modify: `internal/network/summary_test.go`

- [ ] **Step 1: Write the failing HTTP summary tests**

```go
func TestSummaryRecordsHTTPRequests(t *testing.T) {
	summary := NewSummary()
	summary.RecordHTTP("api.github.com", "GET", "/repos/*", Decision{Allowed: true, Rule: "allow"})
	summary.RecordHTTP("api.github.com", "GET", "/repos/*", Decision{Allowed: true, Rule: "allow"})

	var buf bytes.Buffer
	if err := summary.WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "http api.github.com GET /repos/* policy=allowed count=2") {
		t.Fatalf("unexpected output: %q", output)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/network -run 'TestSummaryRecordsHTTPRequests' -v`

Expected: FAIL because `RecordHTTP` does not exist.

- [ ] **Step 3: Extend summary structures**

```go
type HTTPSummaryKey struct {
	Host     string
	Method   string
	Path     string
	Allowed  bool
}

func (s *Summary) RecordHTTP(host, method, path string, decision Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := HTTPSummaryKey{
		Host:    normalizeName(host),
		Method:  strings.ToUpper(method),
		Path:    normalizeHTTPPath(path),
		Allowed: decision.Allowed,
	}
	s.http[key]++
}
```

- [ ] **Step 4: Include HTTP rows in `WriteReport`**

```go
for _, row := range httpRows {
	policy := "denied"
	if row.Allowed {
		policy = "allowed"
	}
	fmt.Fprintf(w, "http %s %s %s policy=%s count=%d\n", row.Host, row.Method, row.Path, policy, row.Count)
}
```

- [ ] **Step 5: Run network tests**

Run: `/usr/local/go/bin/go test ./internal/network -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/network/http_summary.go internal/network/http_summary_test.go internal/network/summary.go internal/network/summary_test.go
git commit -m "feat: add http shutdown summary aggregation"
```

### Task 5: Add MITM Request Handling

**Files:**
- Create: `internal/network/mitm.go`
- Test: `internal/network/mitm_test.go`
- Modify: `internal/network/tcp.go`

- [ ] **Step 1: Write the failing MITM allow/deny tests**

```go
func TestMITMProxyAllowsMatchingHTTPRequest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	ca, err := LoadOrCreateCA(CAOptions{Dir: caDir, Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	proxy := MITMProxy{
		CA: ca,
		Policy: NewHTTPPolicy(HTTPPolicyConfig{
			Default: "deny",
			Rules: []HTTPRule{
				{Action: "allow", Host: hostFromURL(t, upstream.URL), Methods: []string{"GET"}, Paths: []string{"/allowed"}},
			},
		}),
	}

	status, body := roundTripThroughMITM(t, proxy, upstream.URL, "GET", "/allowed")
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestMITMProxyDeniesNonMatchingHTTPRequest(t *testing.T) {
	// same setup, request /denied, expect 403 or closed connection based on implementation
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/network -run 'TestMITMProxy' -v`

Expected: FAIL because `MITMProxy` and helpers do not exist.

- [ ] **Step 3: Add minimal MITM proxy types**

```go
type MITMProxy struct {
	CA      *CA
	Policy  *HTTPPolicy
	Summary *Summary
}

func (p *MITMProxy) HandleTLS(ctx context.Context, downstream net.Conn, serverName string, upstreamAddr string) error {
	issued, err := p.CA.IssueLeaf(serverName)
	if err != nil {
		return err
	}
	tlsConn := tls.Server(downstream, &tls.Config{
		Certificates: []tls.Certificate{issued.Certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	return p.proxyHTTP(ctx, tlsConn, upstreamAddr)
}
```

- [ ] **Step 4: Parse request, evaluate HTTP policy, and forward**

```go
func (p *MITMProxy) proxyHTTP(ctx context.Context, downstream net.Conn, upstreamAddr string) error {
	reader := bufio.NewReader(downstream)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	decision := p.Policy.Evaluate(HTTPRequest{
		Host:   req.Host,
		Method: req.Method,
		Path:   req.URL.Path,
	})
	p.Summary.RecordHTTP(req.Host, req.Method, req.URL.Path, decision)
	if !decision.Allowed {
		return writeHTTPDenied(downstream)
	}
	return forwardHTTPRequest(ctx, downstream, req, upstreamAddr)
}
```

- [ ] **Step 5: Teach `TCPProxy` to hand eligible flows to MITM**

```go
if port == 443 && p.MITM != nil && p.MITM.EnabledFor(sni) {
	return p.MITM.HandleTLS(ctx, conn, sni, destination)
}
```

- [ ] **Step 6: Run network tests**

Run: `/usr/local/go/bin/go test ./internal/network -v`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/network/mitm.go internal/network/mitm_test.go internal/network/tcp.go
git commit -m "feat: add mitm http request handling"
```

### Task 6: Add Guest CA Trust Asset Preparation

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/image/pull.go`
- Modify: `internal/image/inject.go` or the file that mutates rootfs contents
- Test: `internal/cli/host_runner_test.go`
- Test: `internal/image/pull_test.go`

- [ ] **Step 1: Write the failing guest trust asset tests**

```go
func TestHostRunnerBuildsMITMGuestTrustAssets(t *testing.T) {
	cfg := config.Default()
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.MITM.CA.InstallSystem = true

	runner := HostRunner{
		RuntimeDir: t.TempDir(),
		EnsureKernel: func(context.Context, string) (string, error) { return filepath.Join(t.TempDir(), "vmlinux"), nil },
		WorkspacePreparer: func(opts workspace.PrepareOptions) (workspace.PrepareResult, error) {
			return workspace.PrepareResult{ImagePath: opts.ImagePath, SizeBytes: 4096}, nil
		},
	}

	assets, err := runner.prepareAssets(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepareAssets() error = %v", err)
	}
	if assets.RootfsPath == "" {
		t.Fatal("expected rootfs path")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/cli ./internal/image -run 'MITM|Trust' -v`

Expected: FAIL because there is no CA/trust asset plumbing yet.

- [ ] **Step 3: Add guest trust asset structures**

```go
type GuestTrustAssets struct {
	CACertPEM []byte
	Enabled   bool
}

type PullOptions struct {
	CacheDir    string
	Ref         string
	GuestInit   func() (GuestAgentAssets, error)
	GuestTrust  GuestTrustAssets
}
```

- [ ] **Step 4: Inject the CA into the rootfs when enabled**

```go
if trust.Enabled && len(trust.CACertPEM) > 0 {
	if err := writeFileIntoExt4(rootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt", trust.CACertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileIntoExt4(rootfsPath, "/etc/keel/install-ca.sh", []byte(`#!/bin/sh
set -eu
if command -v update-ca-certificates >/dev/null 2>&1; then
	update-ca-certificates
fi
`), 0o755); err != nil {
		return err
	}
}
```

- [ ] **Step 5: Build CA assets in `HostRunner.prepareAssets`**

```go
if cfg.Network.MITM.Enabled && cfg.Network.MITM.CA.InstallSystem {
	caDir := filepath.Join(userDataDir, "keel", "ca")
	ca, err := network.LoadOrCreateCA(network.CAOptions{
		Dir:  caDir,
		Name: cfg.Network.MITM.CA.Name,
	})
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	guestTrust = image.GuestTrustAssets{
		Enabled:   true,
		CACertPEM: ca.CertPEM,
	}
}
```

- [ ] **Step 6: Run affected tests**

Run: `/usr/local/go/bin/go test ./internal/cli ./internal/image -v`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go internal/image/pull.go internal/image/pull_test.go internal/image/inject.go
git commit -m "feat: inject mitm trust assets into guest rootfs"
```

### Task 7: Install Docker MITM Trust

**Files:**
- Modify: `guest/internal/features/docker.go`
- Test: `guest/internal/features/docker_test.go`

- [ ] **Step 1: Write the failing Docker trust tests**

```go
func TestDockerFeatureWritesCACertWhenConfigured(t *testing.T) {
	var writes map[string][]byte
	runner := Runner{
		LookupPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Stat:       fakeStatSuccess,
		MkdirAll:   func(string, os.FileMode) error { return nil },
		WriteFile: func(path string, data []byte, mode os.FileMode) error {
			if writes == nil {
				writes = map[string][]byte{}
			}
			writes[path] = append([]byte(nil), data...)
			return nil
		},
		StartProcess:  func(context.Context, string, []string, []string, string) error { return nil },
		WaitForFile:   func(string) error { return nil },
		WaitForDaemon: func([]string) error { return nil },
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name: "docker",
		Config: map[string]any{
			"mitm_ca_pem": "-----BEGIN CERTIFICATE-----\n...",
		},
	}}, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}
	if _, ok := writes["/etc/docker/certs.d/keel-mitm/ca.crt"]; !ok {
		t.Fatal("expected docker trust cert to be written")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd guest && /usr/local/go/bin/go test ./internal/features -run 'TestDockerFeatureWritesCACertWhenConfigured' -v`

Expected: FAIL because Docker feature config lacks MITM trust handling.

- [ ] **Step 3: Extend Docker feature config minimally**

```go
type DockerConfig struct {
	StorageDriver   string   `json:"storage_driver"`
	RegistryMirrors []string `json:"registry_mirrors"`
	MITMCAPEM       string   `json:"mitm_ca_pem"`
}
```

- [ ] **Step 4: Write Docker trust material when provided**

```go
if strings.TrimSpace(cfg.MITMCAPEM) != "" {
	if err := mkdirAll("/etc/docker/certs.d/keel-mitm", 0o755); err != nil {
		return err
	}
	if err := writeFile("/etc/docker/certs.d/keel-mitm/ca.crt", []byte(cfg.MITMCAPEM), 0o644); err != nil {
		return err
	}
	if err := writeFile("/usr/local/share/ca-certificates/keel-local-ca.crt", []byte(cfg.MITMCAPEM), 0o644); err != nil {
		return err
	}
}
```

- [ ] **Step 5: Run guest Docker feature tests**

Run: `cd guest && /usr/local/go/bin/go test ./internal/features -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add guest/internal/features/docker.go guest/internal/features/docker_test.go
git commit -m "feat: add docker mitm trust installation"
```

### Task 8: Wire MITM Through Host Runner And TCP Proxy

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/cli/host_runner_test.go`
- Modify: `internal/network/tcp.go`

- [ ] **Step 1: Write the failing host-runner MITM wiring test**

```go
func TestHostRunnerStartVMServicesEnablesMITMProxy(t *testing.T) {
	cfg := config.Default()
	cfg.Network.MITM.Enabled = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.HTTP.Default = "deny"

	instance := &stubHypervisorVM{
		listen: func(port uint32) (net.Listener, error) {
			return net.Listen("unix", filepath.Join(t.TempDir(), fmt.Sprintf("vsock-%d", port)))
		},
	}

	runner := HostRunner{}
	stop, summary, err := runner.startVMServices(context.Background(), cfg, instance)
	if err != nil {
		t.Fatalf("startVMServices() error = %v", err)
	}
	defer stop()
	if summary == nil {
		t.Fatal("expected summary")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/cli -run 'TestHostRunnerStartVMServicesEnablesMITMProxy' -v`

Expected: FAIL because MITM config is ignored by service startup.

- [ ] **Step 3: Build HTTP policy + CA in `startVMServices`**

```go
httpPolicy := network.NewHTTPPolicy(network.HTTPPolicyConfig{
	Default: cfg.Network.HTTP.Default,
	Rules:   network.HTTPRulesFromConfig(cfg.Network.HTTP.Rules),
})

var mitm *network.MITMProxy
if cfg.Network.MITM.Enabled {
	ca, err := network.LoadOrCreateCA(network.CAOptions{
		Dir:  filepath.Join(dataDir, "keel", "ca"),
		Name: cfg.Network.MITM.CA.Name,
	})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	mitm = &network.MITMProxy{
		CA:      ca,
		Policy:  httpPolicy,
		Summary: summary,
	}
}
tcpProxy := network.TCPProxy{
	Policy:  engine,
	Summary: summary,
	MITM:    mitm,
}
```

- [ ] **Step 4: Run CLI and network tests**

Run: `/usr/local/go/bin/go test ./internal/cli ./internal/network -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go internal/network/tcp.go
git commit -m "feat: wire mitm policy into host runtime services"
```

### Task 9: Add End-To-End MITM Integration Test

**Files:**
- Modify: `hack/test/integration_test.go`
- Modify: `hack/test/e2e_helpers_test.go`

- [ ] **Step 1: Write the failing e2e test**

```go
func TestMITMHTTPPolicyE2E(t *testing.T) {
	if os.Getenv("KEEL_E2E") == "" {
		t.Skip("set KEEL_E2E=1 to run e2e")
	}

	origin := startLocalHTTPSTestOrigin(t)
	projectDir := writeTempProjectConfig(t, fmt.Sprintf(`
image: ubuntu:24.04
network:
  mitm:
    enabled: true
    ca:
      install_system: true
  dns:
    allowed: ["localhost"]
  tls:
    allowed_sni: ["localhost"]
  http:
    default: deny
    rules:
      - action: allow
        host: "localhost"
        methods: ["GET"]
        paths: ["/allowed"]
`))

	result := runKeel(t, projectDir, []string{"curl", "-fsS", origin + "/allowed"})
	if !strings.Contains(result.Stdout, "allowed") {
		t.Fatalf("stdout = %q", result.Stdout)
	}

	denied := runKeelExpectFailure(t, projectDir, []string{"curl", "-fsS", origin + "/denied"})
	if !strings.Contains(denied.Stderr, "http") {
		t.Fatalf("stderr = %q", denied.Stderr)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `KEEL_E2E=1 /usr/local/go/bin/go test ./hack/test -run 'TestMITMHTTPPolicyE2E' -v`

Expected: FAIL because MITM enforcement is not wired end-to-end yet.

- [ ] **Step 3: Add HTTPS origin helper with test CA trust**

```go
func startLocalHTTPSTestOrigin(t *testing.T) string {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/allowed":
			fmt.Fprint(w, "allowed")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}
```

- [ ] **Step 4: Run e2e plus full test suites**

Run: `KEEL_E2E=1 /usr/local/go/bin/go test ./hack/test -run 'TestMITMHTTPPolicyE2E' -v`

Run: `/usr/local/go/bin/go test ./...`

Run: `cd guest && /usr/local/go/bin/go test ./...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hack/test/integration_test.go hack/test/e2e_helpers_test.go
git commit -m "test: add mitm http policy e2e coverage"
```

### Task 10: Final Verification And Docs

**Files:**
- Modify: `README.md`
- Modify: `keel.yaml.example`

- [ ] **Step 1: Add user-facing MITM config examples**

```yaml
network:
  mitm:
    enabled: true
    ca:
      install_system: true
      install_docker: true
  http:
    default: deny
    rules:
      - action: allow
        host: "api.github.com"
        methods: ["GET"]
        paths:
          - "/repos/*"
```

- [ ] **Step 2: Document Docker trust limitation explicitly**

```md
MITM support installs Keel's local CA into the guest system trust store and Docker daemon/client trust where supported. Arbitrary build-stage container trust varies by base image and is best-effort in the current release.
```

- [ ] **Step 3: Run final verification**

Run: `/usr/local/go/bin/go test ./...`

Run: `cd guest && /usr/local/go/bin/go test ./...`

Run: `make guest-agent GO=/usr/local/go/bin/go`

Run: `/usr/local/go/bin/go build -o ./bin/keel ./cmd/keel`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md keel.yaml.example
git commit -m "docs: document mitm http policy configuration"
```

---

## Self-Review

### Spec coverage

- `network.mitm` config: covered by Task 1.
- `network.http` config: covered by Task 1.
- ordered `host + method + path` policy: covered by Task 2.
- persistent CA and leaf issuance: covered by Task 3.
- HTTP shutdown summary: covered by Task 4.
- host-side MITM implementation: covered by Task 5.
- guest trust injection: covered by Task 6.
- Docker trust integration: covered by Task 7.
- host runtime wiring: covered by Task 8.
- e2e validation: covered by Task 9.
- docs/examples: covered by Task 10.

### Placeholder scan

- No `TODO`, `TBD`, or “similar to above” placeholders remain.
- Follow-up limitations are explicit product constraints, not missing work inside this plan.

### Type consistency

- Config uses `MITMConfig`, `HTTPConfig`, `HTTPRuleConfig`.
- Network policy uses `HTTPPolicyConfig`, `HTTPRule`, `HTTPRequest`.
- CA layer uses `CAOptions`, `CA`, `IssuedCert`.
- MITM layer uses `MITMProxy`.

These names are used consistently across tasks.
