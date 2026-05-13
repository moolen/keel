# Containment Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Keel's over-broad DNS correlation model with strict endpoint rules, make cached base images immutable across runs, and run workloads as non-root by default.

**Architecture:** The network stack will move from separate DNS/TLS/CIDR allowlists to explicit `host+port` endpoint rules and `cidr+port` IP rules, with the tracker carrying scoped endpoint authorizations instead of flat IP-to-domain correlations. Runtime image handling will split immutable cached base images from per-run writable root disks, and process defaults will change so guest bootstrap remains root while the final command runs as UID/GID `65532` unless root is explicitly requested.

**Tech Stack:** Go, Firecracker/vsock transport, ext4 image preparation, existing config/CLI/network/vm/guest packages, Go unit tests.

---

## File Structure

- Modify: `internal/config/config.go`
  Defines the new network rule schema and process defaults.
- Modify: `internal/config/defaults.go`
  Populates strict default config values.
- Modify: `internal/config/loader.go`
  Validates new network fields, rejects removed legacy fields, and applies default process identity semantics.
- Modify: `internal/config/loader_test.go`
  Covers new config parsing, validation, and migration-failure behavior.
- Modify: `internal/network/policy.go`
  Replaces broad DNS-correlation semantics with endpoint/IP rule evaluation.
- Modify: `internal/network/tracker.go`
  Stores scoped endpoint authorizations keyed by resolved IP, hostname, port, and expiry.
- Modify: `internal/network/dns.go`
  Uses endpoint rules to decide DNS allow/refuse behavior and records scoped authorizations.
- Modify: `internal/network/tcp.go`
  Evaluates flows against endpoint authorizations and direct-IP rules; enforces per-rule SNI behavior.
- Modify: `internal/network/http_policy.go`
  Keep behavior intact, but update any references to old transport config types if needed.
- Modify: `internal/network/policy_test.go`
  Covers endpoint semantics, shared-IP denial, direct-IP denial, and per-rule SNI behavior.
- Modify: `internal/network/dns_test.go`
  Covers endpoint-based DNS authorization and recording behavior.
- Modify: `internal/network/tcp_test.go`
  Covers endpoint/IP rule transport decisions at the proxy layer.
- Modify: `internal/cli/host_runner.go`
  Copies immutable cached base rootfs to a per-run writable runtime rootfs, builds new network policy services, and defaults omitted process config.
- Modify: `internal/cli/host_runner_test.go`
  Covers runtime rootfs copy behavior, immutable cache behavior, and default process propagation.
- Modify: `internal/image/cache.go`
  Introduces explicit cached base image path naming if needed.
- Modify: `internal/image/pull.go`
  Produces immutable prepared base images instead of directly returning a writable runtime rootfs.
- Modify: `internal/vm/machine.go`
  Boots from the per-run runtime rootfs path instead of the cached base image path.
- Modify: `internal/vm/machine_test.go`
  Covers root-drive path selection.
- Modify: `guest/internal/pty.go`
  Applies default unprivileged credentials when process config is omitted.
- Modify: `guest/internal/pty_test.go`
  Covers default non-root behavior and explicit root opt-in.
- Modify: `guest/internal/agent/agent.go`
  Keeps manifest/process propagation aligned with the new defaulting behavior if needed.
- Modify: `guest/internal/agent/agent_test.go`
  Covers process propagation with omitted and explicit config.
- Modify: `README.md`
  Documents the new endpoint/IP policy model and rootfs/runtime semantics.
- Modify: `keel.yaml.example`
  Shows the new config shape.

### Task 1: Replace The Network Config Schema

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader.go`
- Test: `internal/config/loader_test.go`

- [ ] **Step 1: Write failing loader tests for endpoint rules, IP rules, and legacy-field rejection**

Add tests like:

```go
func TestLoadParsesEndpointAndIPRules(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	configYAML := `
network:
  endpoints:
    - host: api.github.com
      port: 443
    - host: packages.example.internal
      port: 8443
      tls:
        require_sni_match: false
  ip_rules:
    - cidr: 10.20.0.0/16
      port: 5432
`
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Network.Endpoints) != 2 {
		t.Fatalf("len(cfg.Network.Endpoints) = %d, want 2", len(cfg.Network.Endpoints))
	}
	if got := cfg.Network.Endpoints[0]; got.Host != "api.github.com" || got.Port != 443 {
		t.Fatalf("first endpoint = %#v", got)
	}
	if got := cfg.Network.IPRules[0]; got.CIDR != "10.20.0.0/16" || got.Port != 5432 {
		t.Fatalf("first ip rule = %#v", got)
	}
}

func TestLoadRejectsLegacyNetworkFields(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	configYAML := `
network:
  dns:
    allowed: ["api.github.com"]
`
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(LoadOptions{WorkingDir: projectDir})
	if err == nil || !strings.Contains(err.Error(), "network.dns") {
		t.Fatalf("Load() error = %v, want legacy network.dns rejection", err)
	}
}
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run:

```bash
go test ./internal/config -run 'TestLoadParsesEndpointAndIPRules|TestLoadRejectsLegacyNetworkFields' -v
```

Expected: FAIL because `NetworkConfig` has no `Endpoints` / `IPRules` fields and loader validation still accepts the legacy schema.

- [ ] **Step 3: Add the new config types**

Update `internal/config/config.go` with the new structs:

```go
type NetworkConfig struct {
	Mode                string               `yaml:"mode"`
	Audit               bool                 `yaml:"audit"`
	DenyUnresolvedHosts bool                 `yaml:"deny_unresolved_hosts"`
	Endpoints           []EndpointRuleConfig `yaml:"endpoints"`
	IPRules             []IPRuleConfig       `yaml:"ip_rules"`
	MITM                MITMConfig           `yaml:"mitm"`
	HTTP                HTTPConfig           `yaml:"http"`
	LogDecisions        bool                 `yaml:"-"`
}

type EndpointRuleConfig struct {
	Host string            `yaml:"host"`
	Port int               `yaml:"port"`
	TLS  EndpointTLSConfig `yaml:"tls"`
}

type EndpointTLSConfig struct {
	RequireSNIMatch *bool `yaml:"require_sni_match"`
}

type IPRuleConfig struct {
	CIDR string `yaml:"cidr"`
	Port int    `yaml:"port"`
}
```

- [ ] **Step 4: Set strict defaults for the new network model**

Update `internal/config/defaults.go` so the default network config becomes:

```go
Network: NetworkConfig{
	Mode:                "vsock",
	Audit:               false,
	DenyUnresolvedHosts: true,
	Endpoints:           []EndpointRuleConfig{},
	IPRules:             []IPRuleConfig{},
	MITM: MITMConfig{
		Mode:            "optional",
		OnUntrustedCert: "deny",
		Bypass: MITMBypassConfig{
			Hosts: []string{},
			SNI:   []string{},
		},
	},
	HTTP: HTTPConfig{
		Default: "deny",
		Rules:   []HTTPRuleConfig{},
	},
},
```

- [ ] **Step 5: Update loader validation and reject legacy transport fields**

In `internal/config/loader.go`, add validation that:

```go
func validateNetwork(cfg NetworkConfig) error {
	for _, rule := range cfg.Endpoints {
		if strings.TrimSpace(rule.Host) == "" {
			return errors.New("network.endpoints.host is required")
		}
		if rule.Port <= 0 || rule.Port > 65535 {
			return errors.New("network.endpoints.port must be between 1 and 65535")
		}
	}
	for _, rule := range cfg.IPRules {
		if strings.TrimSpace(rule.CIDR) == "" {
			return errors.New("network.ip_rules.cidr is required")
		}
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return fmt.Errorf("network.ip_rules.cidr %q is invalid", rule.CIDR)
		}
		if rule.Port <= 0 || rule.Port > 65535 {
			return errors.New("network.ip_rules.port must be between 1 and 65535")
		}
	}
	return nil
}
```

Also reject legacy transport fields with targeted errors when present in parsed YAML, for example:

```go
if presence.Network != nil && presence.Network.DNS != nil {
	return errors.New("network.dns is no longer supported; use network.endpoints instead")
}
```

- [ ] **Step 6: Run the config tests to verify they pass**

Run:

```bash
go test ./internal/config -run 'TestLoadParsesEndpointAndIPRules|TestLoadRejectsLegacyNetworkFields' -v
```

Expected: PASS.

- [ ] **Step 7: Commit the config schema migration**

```bash
git add internal/config/config.go internal/config/defaults.go internal/config/loader.go internal/config/loader_test.go
git commit -m "refactor: replace legacy transport config with endpoint rules"
```

### Task 2: Rewrite Policy Evaluation And Tracking

**Files:**
- Modify: `internal/network/policy.go`
- Modify: `internal/network/tracker.go`
- Modify: `internal/network/dns.go`
- Modify: `internal/network/tcp.go`
- Test: `internal/network/policy_test.go`
- Test: `internal/network/dns_test.go`
- Test: `internal/network/tcp_test.go`

- [ ] **Step 1: Write failing policy tests for shared-IP denial, port scoping, direct-IP denial, and per-rule SNI behavior**

Add tests like:

```go
func TestPolicyDoesNotAuthorizeSiblingHostOnSharedIP(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		DenyUnresolvedHosts: true,
		Endpoints: []EndpointRule{
			{Host: "api.github.com", Port: 443, RequireSNIMatch: true},
		},
	}, tracker)

	tracker.ObserveEndpoint("api.github.com", net.ParseIP("140.82.112.6"), 443, 30*time.Second, time.Unix(100, 0))

	decision := engine.EvaluateEndpointTCP(net.ParseIP("140.82.112.6"), 443, "gist.github.com", time.Unix(110, 0))
	if decision.Allowed {
		t.Fatalf("EvaluateEndpointTCP() = %+v, want deny", decision)
	}
}

func TestPolicyDeniesDirectIPWithoutMatchingRule(t *testing.T) {
	engine := NewPolicyEngine(PolicyConfig{
		DenyUnresolvedHosts: true,
	}, NewTracker(60*time.Second))

	decision := engine.EvaluateDirectTCP(net.ParseIP("10.20.1.15"), 5432)
	if decision.Allowed {
		t.Fatalf("EvaluateDirectTCP() = %+v, want deny", decision)
	}
}

func TestPolicyAllowsDirectIPOnlyWhenCIDRAndPortMatch(t *testing.T) {
	engine := NewPolicyEngine(PolicyConfig{
		IPRules: []IPRule{
			{CIDR: "10.20.0.0/16", Port: 5432},
		},
	}, NewTracker(60*time.Second))

	if got := engine.EvaluateDirectTCP(net.ParseIP("10.20.1.15"), 5432); !got.Allowed {
		t.Fatalf("allowed rule denied: %+v", got)
	}
	if got := engine.EvaluateDirectTCP(net.ParseIP("10.20.1.15"), 443); got.Allowed {
		t.Fatalf("unexpected allow on wrong port: %+v", got)
	}
}
```

- [ ] **Step 2: Run the network policy tests to verify they fail**

Run:

```bash
go test ./internal/network -run 'TestPolicyDoesNotAuthorizeSiblingHostOnSharedIP|TestPolicyDeniesDirectIPWithoutMatchingRule|TestPolicyAllowsDirectIPOnlyWhenCIDRAndPortMatch' -v
```

Expected: FAIL because the old `PolicyConfig` and tracker API do not express endpoint-scoped authorization.

- [ ] **Step 3: Replace the policy config types and decisions**

Refactor `internal/network/policy.go` around explicit rule types:

```go
type EndpointRule struct {
	Host            string
	Port            int
	RequireSNIMatch bool
}

type IPRule struct {
	CIDR string
	Port int
}

type PolicyConfig struct {
	Audit               bool
	DenyUnresolvedHosts bool
	Endpoints           []EndpointRule
	IPRules             []IPRule
	HTTP                HTTPPolicyConfig
}
```

Implement helpers:

```go
func (e *PolicyEngine) MatchEndpointHost(host string) []EndpointRule
func (e *PolicyEngine) EvaluateDNSHost(host string) Decision
func (e *PolicyEngine) EvaluateEndpointTCP(ip net.IP, port int, sni string, now time.Time) Decision
func (e *PolicyEngine) EvaluateDirectTCP(ip net.IP, port int) Decision
```

- [ ] **Step 4: Replace tracker storage with scoped endpoint authorizations**

Refactor `internal/network/tracker.go` to store entries like:

```go
type trackedEndpoint struct {
	host      string
	port      int
	expiresAt time.Time
}

type Tracker struct {
	minTTL time.Duration
	mu     sync.RWMutex
	byIP   map[string][]trackedEndpoint
}

func (t *Tracker) ObserveEndpoint(host string, ip net.IP, port int, ttl time.Duration, now time.Time) {
	// append scoped authorization
}

func (t *Tracker) Endpoints(ip net.IP, port int, now time.Time) []trackedEndpoint {
	// return only unexpired entries for this IP and port
}
```

- [ ] **Step 5: Update DNS proxy to authorize only configured endpoint hosts and record scoped endpoint entries**

In `internal/network/dns.go`, change evaluation flow to:

```go
decision := p.Policy.EvaluateDNSHost(query.Question[0].Name)
if !decision.Allowed {
	// refuse query
}

matched := p.Policy.MatchEndpointHost(query.Question[0].Name)
reply, err := resolver.Exchange(ctx, query)
// ...
for _, answer := range reply.Answer {
	if rr, ok := answer.(*dns.A); ok {
		for _, rule := range matched {
			p.Tracker.ObserveEndpoint(query.Question[0].Name, rr.A, rule.Port, time.Duration(rr.Hdr.Ttl)*time.Second, now)
		}
	}
}
```

- [ ] **Step 6: Update TCP proxy to distinguish direct-IP rules from endpoint-authorized flows**

In `internal/network/tcp.go`, after parsing destination and optional SNI, use:

```go
decision := p.Policy.EvaluateEndpointTCP(ip, port, sni, now)
if !decision.Allowed {
	decision = p.Policy.EvaluateDirectTCP(ip, port)
}
```

Inside `EvaluateEndpointTCP`, require:

```go
entries := e.tracker.Endpoints(ip, port, now)
if len(entries) == 0 {
	return e.applyAudit(Decision{Reason: "destination ip not authorized for endpoint", Rule: "default"})
}

authorized := false
for _, entry := range entries {
	if !entryRequiresSNIMatch(entry, port) {
		authorized = true
		break
	}
	if sni != "" && normalizeName(sni) == normalizeName(entry.host) {
		authorized = true
		break
	}
}
if !authorized {
	return e.applyAudit(Decision{Reason: "sni does not match authorized endpoint", Rule: "default"})
}
```

- [ ] **Step 7: Run the focused network tests to verify they pass**

Run:

```bash
go test ./internal/network -run 'TestPolicyDoesNotAuthorizeSiblingHostOnSharedIP|TestPolicyDeniesDirectIPWithoutMatchingRule|TestPolicyAllowsDirectIPOnlyWhenCIDRAndPortMatch' -v
```

Expected: PASS.

- [ ] **Step 8: Add proxy-level tests for DNS refusal and port scoping**

Add targeted tests such as:

```go
func TestDNSProxyRefusesHostWithoutEndpointRule(t *testing.T) { /* ... */ }
func TestTCPProxyDeniesEndpointAuthorizationOnWrongPort(t *testing.T) { /* ... */ }
func TestTCPProxyAllowsEndpointAuthorizationOnMatchingPortAndSNI(t *testing.T) { /* ... */ }
```

- [ ] **Step 9: Run the full network package tests**

Run:

```bash
go test ./internal/network/... -v
```

Expected: PASS.

- [ ] **Step 10: Commit the network policy rewrite**

```bash
git add internal/network/policy.go internal/network/tracker.go internal/network/dns.go internal/network/tcp.go internal/network/policy_test.go internal/network/dns_test.go internal/network/tcp_test.go
git commit -m "refactor: enforce endpoint-scoped egress policy"
```

### Task 3: Make Cached Rootfs Immutable Across Runs

**Files:**
- Modify: `internal/image/cache.go`
- Modify: `internal/image/pull.go`
- Modify: `internal/cli/host_runner.go`
- Modify: `internal/vm/machine.go`
- Test: `internal/cli/host_runner_test.go`
- Test: `internal/vm/machine_test.go`

- [ ] **Step 1: Write failing tests for per-run runtime rootfs copies**

Add tests like:

```go
func TestPrepareAssetsCopiesCachedBaseRootfsIntoRuntimeDir(t *testing.T) {
	cacheDir := t.TempDir()
	rootfsPath := filepath.Join(cacheDir, "index.docker.io", "library", "ubuntu", "24.04", "base.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfsPath, []byte("base-rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := HostRunner{
		EnsureKernel: func(context.Context, string) (string, error) { return filepath.Join(t.TempDir(), "vmlinux"), nil },
		GuestAssets: func() (image.GuestAgentAssets, error) { return image.GuestAgentAssets{}, nil },
	}

	_ = runner
	// Assert returned RuntimeAssets.RootfsPath is in runtime dir, not cache path.
}
```

and:

```go
func TestMachineBuildsHypervisorConfigFromRuntimeRootfsPath(t *testing.T) {
	m := NewMachine(config.Config{}, RuntimeAssets{
		KernelPath:    "/tmp/kernel",
		RootfsPath:    "/tmp/runtime/rootfs.ext4",
		WorkspacePath: "/tmp/runtime/workspace.ext4",
		MetadataPath:  "/tmp/runtime/meta.ext4",
		SocketPath:    "/tmp/runtime/fc.sock",
		VSockPath:     "/tmp/runtime/vsock",
		CID:           3,
	})

	hvCfg, err := m.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	if hvCfg.RootDrive.Path != "/tmp/runtime/rootfs.ext4" {
		t.Fatalf("RootDrive.Path = %q", hvCfg.RootDrive.Path)
	}
}
```

- [ ] **Step 2: Run the focused runtime tests to verify they fail**

Run:

```bash
go test ./internal/cli ./internal/vm -run 'TestPrepareAssetsCopiesCachedBaseRootfsIntoRuntimeDir|TestMachineBuildsHypervisorConfigFromRuntimeRootfsPath' -v
```

Expected: FAIL because the runtime still boots directly from the cached rootfs path.

- [ ] **Step 3: Rename cache layout rootfs artifact to an immutable base-image path**

In `internal/image/cache.go`, change:

```go
type CacheLayout struct {
	Registry       string
	Repository     string
	Tag            string
	Directory      string
	BaseRootfsPath string
	OCIPath        string
	AgentPath      string
}
```

and:

```go
BaseRootfsPath: filepath.Join(dir, "base.ext4"),
```

Update all uses in `internal/image/pull.go` accordingly.

- [ ] **Step 4: Copy the immutable base image into the runtime dir during asset preparation**

In `internal/cli/host_runner.go`, after creating `runtimeDir`, add:

```go
runtimeRootfsPath := filepath.Join(runtimeDir, "rootfs.ext4")
if err := copyFile(layout.BaseRootfsPath, runtimeRootfsPath); err != nil {
	return vm.RuntimeAssets{}, fmt.Errorf("copy runtime rootfs: %w", err)
}
```

Add a helper in the same file or a small adjacent utility:

```go
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
```

Populate `vm.RuntimeAssets.RootfsPath` with `runtimeRootfsPath`, not the cache path.

- [ ] **Step 5: Keep image preparation operating on the cached immutable base**

Update `internal/image/pull.go` and rootfs-injection call sites so:

```go
CreateRootfsImage(CreateRootfsOptions{
	SourceDir: tempDir,
	ImagePath: layout.BaseRootfsPath,
	SizeMB:    2048,
})
```

and all `EnsureGuestAgent`, `InjectGuestTrust`, and feature-preparation calls operate on `layout.BaseRootfsPath`.

- [ ] **Step 6: Run the focused runtime tests to verify they pass**

Run:

```bash
go test ./internal/cli ./internal/vm -run 'TestPrepareAssetsCopiesCachedBaseRootfsIntoRuntimeDir|TestMachineBuildsHypervisorConfigFromRuntimeRootfsPath' -v
```

Expected: PASS.

- [ ] **Step 7: Add a regression test proving runtime rootfs mutation does not affect the cached base path**

Add a test that:

```go
func TestPrepareAssetsLeavesCachedBaseRootfsUnchanged(t *testing.T) {
	// create base.ext4 placeholder
	// call prepareAssets
	// mutate returned runtime rootfs file
	// reread base.ext4 and assert original bytes are unchanged
}
```

- [ ] **Step 8: Run all CLI/VM tests**

Run:

```bash
go test ./internal/cli ./internal/vm -v
```

Expected: PASS.

- [ ] **Step 9: Commit the immutable-base runtime split**

```bash
git add internal/image/cache.go internal/image/pull.go internal/cli/host_runner.go internal/cli/host_runner_test.go internal/vm/machine.go internal/vm/machine_test.go
git commit -m "fix: isolate runtime rootfs from cached base image"
```

### Task 4: Default Workloads To An Unprivileged Identity

**Files:**
- Modify: `internal/config/defaults.go`
- Modify: `internal/config/loader.go`
- Modify: `internal/cli/host_runner.go`
- Modify: `guest/internal/pty.go`
- Test: `guest/internal/pty_test.go`
- Test: `guest/internal/agent/agent_test.go`
- Test: `internal/config/loader_test.go`

- [ ] **Step 1: Write failing tests for omitted process config using UID/GID 65532**

Add tests like:

```go
func TestConfigureCommandCredentialDefaultsToUnprivilegedIdentity(t *testing.T) {
	cmd := exec.Command("/bin/true")

	configureCommandCredential(cmd, nil)

	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("Credential = nil, want default credential")
	}
	cred := cmd.SysProcAttr.Credential
	if cred.Uid != 65532 || cred.Gid != 65532 {
		t.Fatalf("default credential = %+v, want uid/gid 65532", cred)
	}
}

func TestLoadDefaultsProcessToUnprivilegedIdentity(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Process == nil || cfg.Process.UID != 65532 || cfg.Process.GID != 65532 {
		t.Fatalf("cfg.Process = %#v, want default unprivileged process", cfg.Process)
	}
}
```

- [ ] **Step 2: Run the focused process tests to verify they fail**

Run:

```bash
go test ./internal/config ./guest/internal -run 'TestLoadDefaultsProcessToUnprivilegedIdentity|TestConfigureCommandCredentialDefaultsToUnprivilegedIdentity' -v
```

Expected: FAIL because omitted process config currently stays nil and `configureCommandCredential` is a no-op for nil.

- [ ] **Step 3: Introduce a shared default process identity**

In `internal/config/defaults.go`, set:

```go
Process: &ProcessConfig{
	UID:    65532,
	GID:    65532,
	hasUID: true,
	hasGID: true,
},
```

If keeping defaults out of the static struct is cleaner, add a helper:

```go
func DefaultProcessConfig() *ProcessConfig {
	return &ProcessConfig{
		UID:    65532,
		GID:    65532,
		hasUID: true,
		hasGID: true,
	}
}
```

and use it from defaults/loader.

- [ ] **Step 4: Preserve explicit root opt-in and process override semantics**

Update `internal/config/loader.go` so:

```go
if dst.Process == nil {
	dst.Process = DefaultProcessConfig()
}
```

and explicit YAML values still overwrite defaults, including `uid: 0` / `gid: 0`.

- [ ] **Step 5: Apply default credentials in the guest PTY launcher**

In `guest/internal/pty.go`, replace the nil short-circuit with:

```go
func configureCommandCredential(cmd *exec.Cmd, process *ProcessConfig) {
	if process == nil {
		process = &ProcessConfig{UID: 65532, GID: 65532}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid:    uint32(process.UID),
		Gid:    uint32(process.GID),
		Groups: supplementaryGroups(process.SupplementaryGIDs),
	}
}
```

- [ ] **Step 6: Add an explicit root regression test**

Add:

```go
func TestConfigureCommandCredentialPreservesExplicitRoot(t *testing.T) {
	cmd := exec.Command("/bin/true")

	configureCommandCredential(cmd, &ProcessConfig{UID: 0, GID: 0})

	cred := cmd.SysProcAttr.Credential
	if cred.Uid != 0 || cred.Gid != 0 {
		t.Fatalf("credential = %+v, want explicit root", cred)
	}
}
```

- [ ] **Step 7: Run the focused process tests to verify they pass**

Run:

```bash
go test ./internal/config ./guest/internal -run 'TestLoadDefaultsProcessToUnprivilegedIdentity|TestConfigureCommandCredentialDefaultsToUnprivilegedIdentity|TestConfigureCommandCredentialPreservesExplicitRoot' -v
```

Expected: PASS.

- [ ] **Step 8: Add a host-runner/agent regression test for manifest propagation**

Add a test that verifies `buildBootManifest` receives the default process identity when the user omits `process`, and that explicit `uid: 0` / `gid: 0` still propagates as root.

- [ ] **Step 9: Run all guest and config tests**

Run:

```bash
go test ./internal/config -v
cd guest && go test ./... -v
```

Expected: PASS.

- [ ] **Step 10: Commit the default non-root process change**

```bash
git add internal/config/defaults.go internal/config/loader.go internal/config/loader_test.go internal/cli/host_runner.go guest/internal/pty.go guest/internal/pty_test.go guest/internal/agent/agent_test.go
git commit -m "fix: run workloads as non-root by default"
```

### Task 5: Wire The New Config Into Services And Update Docs

**Files:**
- Modify: `internal/cli/host_runner.go`
- Modify: `README.md`
- Modify: `keel.yaml.example`
- Test: `internal/cli/host_runner_test.go`

- [ ] **Step 1: Write failing tests for service construction using endpoint/IP rules**

Add a test like:

```go
func TestBuildNetworkServicesUsesEndpointAndIPRules(t *testing.T) {
	cfg := config.Config{
		Network: config.NetworkConfig{
			DenyUnresolvedHosts: true,
			Endpoints: []config.EndpointRuleConfig{
				{Host: "api.github.com", Port: 443},
			},
			IPRules: []config.IPRuleConfig{
				{CIDR: "10.20.0.0/16", Port: 5432},
			},
		},
	}

	_, tcpProxy, _, err := buildNetworkServices(cfg)
	if err != nil {
		t.Fatalf("buildNetworkServices() error = %v", err)
	}
	if tcpProxy.Policy == nil {
		t.Fatal("tcpProxy.Policy = nil")
	}
}
```

- [ ] **Step 2: Run the focused service test to verify it fails**

Run:

```bash
go test ./internal/cli -run TestBuildNetworkServicesUsesEndpointAndIPRules -v
```

Expected: FAIL because `buildNetworkServices` still constructs the old `PolicyConfig`.

- [ ] **Step 3: Update `buildNetworkServices` to map config endpoint/IP rules into the new policy engine**

In `internal/cli/host_runner.go`, build:

```go
endpoints := make([]network.EndpointRule, 0, len(cfg.Network.Endpoints))
for _, item := range cfg.Network.Endpoints {
	requireSNI := item.Port == 443
	if item.TLS.RequireSNIMatch != nil {
		requireSNI = *item.TLS.RequireSNIMatch
	}
	endpoints = append(endpoints, network.EndpointRule{
		Host:            item.Host,
		Port:            item.Port,
		RequireSNIMatch: requireSNI,
	})
}

ipRules := make([]network.IPRule, 0, len(cfg.Network.IPRules))
for _, item := range cfg.Network.IPRules {
	ipRules = append(ipRules, network.IPRule{
		CIDR: item.CIDR,
		Port: item.Port,
	})
}

engine := network.NewPolicyEngine(network.PolicyConfig{
	Audit:               cfg.Network.Audit,
	DenyUnresolvedHosts: cfg.Network.DenyUnresolvedHosts,
	Endpoints:           endpoints,
	IPRules:             ipRules,
	HTTP:                httpPolicy,
}, tracker)
```

- [ ] **Step 4: Update README and sample config to the new policy model**

In `keel.yaml.example`, replace legacy transport settings with:

```yaml
network:
  audit: false
  deny_unresolved_hosts: true
  endpoints:
    - host: api.github.com
      port: 443
    - host: auth.docker.io
      port: 443
  ip_rules:
    - cidr: 10.20.0.0/16
      port: 5432
```

In `README.md`, update:

- the “Full keel.yaml” section
- the policy/audit examples
- the explanation of what a named endpoint rule means
- the note that direct IP egress is denied unless `ip_rules` permits it
- the note that the cached base rootfs is immutable and each run uses a runtime copy
- the note that workloads run non-root by default and root is explicit

- [ ] **Step 5: Run the focused CLI service test to verify it passes**

Run:

```bash
go test ./internal/cli -run TestBuildNetworkServicesUsesEndpointAndIPRules -v
```

Expected: PASS.

- [ ] **Step 6: Run the full verification suite**

Run:

```bash
go test ./internal/network/... ./internal/config ./internal/cli ./internal/vm -v
cd guest && go test ./... -v
```

Expected: PASS.

- [ ] **Step 7: Commit the service wiring and documentation update**

```bash
git add internal/cli/host_runner.go internal/cli/host_runner_test.go README.md keel.yaml.example
git commit -m "docs: update runtime and network policy semantics"
```

## Self-Review

Spec coverage:

- Network endpoint/IP redesign: covered by Tasks 1, 2, and 5.
- Immutable cached base image and per-run writable root disk: covered by Task 3.
- Default non-root workload identity with explicit root opt-in: covered by Task 4.
- Docs and migration stance: covered by Tasks 1 and 5.

Placeholder scan:

- No `TODO`, `TBD`, or “similar to above” placeholders remain.

Type consistency:

- Plan uses `EndpointRuleConfig`, `IPRuleConfig`, `EndpointRule`, `IPRule`, `ObserveEndpoint`, `Endpoints`, `EvaluateDNSHost`, `EvaluateEndpointTCP`, and `EvaluateDirectTCP` consistently across tasks.
