package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMergedConfig(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	globalDir := filepath.Join(homeDir, ".config", "keel")
	projectDir := filepath.Join(t.TempDir(), "project", "nested")

	mkdirAll(t, globalDir)
	mkdirAll(t, projectDir)

	writeFile(t, filepath.Join(globalDir, "config.yaml"), `
image_cache_dir: ~/.cache/custom-keel/images
kernel_path: /opt/keel/vmlinux
default_resources:
  vcpu: 3
  memory_mb: 3072
  disk_mb: 6144
network:
  dns:
    allowed:
      - "*.github.com"
`)

	writeFile(t, filepath.Join(filepath.Dir(projectDir), "keel.yaml"), `
image: debian:bookworm
workspace:
  target: /src
  sync_back: true
network:
  deny_if_no_sni: true
  dns:
    denied:
      - "api.github.com"
features:
  - name: docker
    config:
      storage_driver: overlay2
env:
  CI: "1"
`)

	cfg, err := Load(LoadOptions{
		WorkingDir: projectDir,
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Image != "debian:bookworm" {
		t.Fatalf("cfg.Image = %q, want debian:bookworm", cfg.Image)
	}
	if cfg.ImageCacheDir != filepath.Join(homeDir, ".cache", "custom-keel", "images") {
		t.Fatalf("cfg.ImageCacheDir = %q", cfg.ImageCacheDir)
	}
	if cfg.Kernel.Path != "/opt/keel/vmlinux" {
		t.Fatalf("cfg.Kernel.Path = %q", cfg.Kernel.Path)
	}
	if cfg.Resources.VCPU != 3 || cfg.Resources.MemoryMB != 3072 || cfg.Resources.DiskMB != 6144 {
		t.Fatalf("unexpected resources: %+v", cfg.Resources)
	}
	if cfg.Workspace.Target != "/src" || !cfg.Workspace.SyncBack || !cfg.Workspace.SyncConfirm {
		t.Fatalf("unexpected workspace config: %+v", cfg.Workspace)
	}
	if !cfg.Network.DenyIfNoSNI {
		t.Fatal("cfg.Network.DenyIfNoSNI = false, want true")
	}
	if len(cfg.Network.DNS.Allowed) != 1 || cfg.Network.DNS.Allowed[0] != "*.github.com" {
		t.Fatalf("unexpected DNS allowed rules: %#v", cfg.Network.DNS.Allowed)
	}
	if len(cfg.Network.DNS.Denied) != 1 || cfg.Network.DNS.Denied[0] != "api.github.com" {
		t.Fatalf("unexpected DNS denied rules: %#v", cfg.Network.DNS.Denied)
	}
	if len(cfg.Features) != 1 || cfg.Features[0].Name != "docker" {
		t.Fatalf("unexpected features: %#v", cfg.Features)
	}
	if cfg.Env["CI"] != "1" || cfg.Env["TERM"] != "xterm-256color" {
		t.Fatalf("unexpected env: %#v", cfg.Env)
	}
}

func TestLoadUsesGlobalImageOverride(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	globalDir := filepath.Join(homeDir, ".config", "keel")
	projectDir := t.TempDir()
	mkdirAll(t, globalDir)
	writeFile(t, filepath.Join(projectDir, "keel.yaml"), "workspace:\n  target: /workspace\n")

	writeFile(t, filepath.Join(globalDir, "config.yaml"), `
image: busybox:latest
image_cache_dir: ~/.cache/custom-keel/images
`)

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Image != "busybox:latest" {
		t.Fatalf("cfg.Image = %q, want busybox:latest", cfg.Image)
	}
}

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
    bypass:
      hosts:
        - registry.npmjs.org
      sni:
        - "*.github.com"
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
	if got, want := cfg.Network.MITM.Mode, "optional"; got != want {
		t.Fatalf("MITM mode = %q, want %q", got, want)
	}
	if got, want := cfg.Network.MITM.OnUntrustedCert, "deny"; got != want {
		t.Fatalf("MITM on_untrusted_cert = %q, want %q", got, want)
	}
	if !cfg.Network.MITM.LogRequests {
		t.Fatal("MITM log_requests should be true from global config")
	}
	if got, want := cfg.Network.MITM.CA.Name, "keel-local-ca"; got != want {
		t.Fatalf("MITM CA name = %q, want %q", got, want)
	}
	if !cfg.Network.MITM.CA.InstallSystem || !cfg.Network.MITM.CA.InstallDocker {
		t.Fatalf("unexpected MITM CA flags: %+v", cfg.Network.MITM.CA)
	}
	if len(cfg.Network.MITM.Bypass.Hosts) != 1 || cfg.Network.MITM.Bypass.Hosts[0] != "registry.npmjs.org" {
		t.Fatalf("unexpected MITM bypass hosts: %#v", cfg.Network.MITM.Bypass.Hosts)
	}
	if len(cfg.Network.MITM.Bypass.SNI) != 1 || cfg.Network.MITM.Bypass.SNI[0] != "*.github.com" {
		t.Fatalf("unexpected MITM bypass SNI: %#v", cfg.Network.MITM.Bypass.SNI)
	}
	if got, want := cfg.Network.HTTP.Default, "deny"; got != want {
		t.Fatalf("HTTP default = %q, want %q", got, want)
	}
	if len(cfg.Network.HTTP.Rules) != 1 {
		t.Fatalf("len(HTTP.Rules) = %d, want 1", len(cfg.Network.HTTP.Rules))
	}
	if got, want := cfg.Network.HTTP.Rules[0].Action, "allow"; got != want {
		t.Fatalf("HTTP rule action = %q, want %q", got, want)
	}
	if got, want := cfg.Network.HTTP.Rules[0].Host, "api.github.com"; got != want {
		t.Fatalf("HTTP rule host = %q, want %q", got, want)
	}
	if len(cfg.Network.HTTP.Rules[0].Methods) != 1 || cfg.Network.HTTP.Rules[0].Methods[0] != "GET" {
		t.Fatalf("unexpected HTTP rule methods: %#v", cfg.Network.HTTP.Rules[0].Methods)
	}
	if len(cfg.Network.HTTP.Rules[0].Paths) != 1 || cfg.Network.HTTP.Rules[0].Paths[0] != "/repos/*" {
		t.Fatalf("unexpected HTTP rule paths: %#v", cfg.Network.HTTP.Rules[0].Paths)
	}
}

func TestLoadMITMAndHTTPProjectOverridesCanDisableAndClear(t *testing.T) {
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
    mode: required
    on_untrusted_cert: allow
    log_requests: true
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true
    bypass:
      hosts:
        - registry.npmjs.org
      sni:
        - "*.github.com"
  http:
    default: allow
    rules:
      - action: deny
        host: api.github.com
        methods: ["POST"]
        paths: ["/repos/private/*"]
`)
	if err := os.WriteFile(filepath.Join(tmpHome, ".config", "keel", "config.yaml"), globalConfig, 0o644); err != nil {
		t.Fatal(err)
	}

	projectConfig := []byte(`
network:
  mitm:
    enabled: false
    log_requests: false
    ca:
      install_system: false
      install_docker: false
    bypass:
      hosts: []
      sni:
        - api.stripe.com
  http:
    default: deny
    rules: []
`)
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), projectConfig, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Network.MITM.Enabled {
		t.Fatal("MITM enabled should be overridable to false in project config")
	}
	if cfg.Network.MITM.LogRequests {
		t.Fatal("MITM log_requests should be overridable to false in project config")
	}
	if got, want := cfg.Network.MITM.Mode, "required"; got != want {
		t.Fatalf("MITM mode should remain inherited when omitted = %q, want %q", got, want)
	}
	if got, want := cfg.Network.MITM.OnUntrustedCert, "allow"; got != want {
		t.Fatalf("MITM on_untrusted_cert should remain inherited when omitted = %q, want %q", got, want)
	}
	if got, want := cfg.Network.MITM.CA.Name, "keel-local-ca"; got != want {
		t.Fatalf("MITM CA name should remain inherited when omitted = %q, want %q", got, want)
	}
	if cfg.Network.MITM.CA.InstallSystem || cfg.Network.MITM.CA.InstallDocker {
		t.Fatalf("MITM CA flags should be overridable to false: %+v", cfg.Network.MITM.CA)
	}
	if len(cfg.Network.MITM.Bypass.Hosts) != 0 {
		t.Fatalf("MITM bypass hosts should be clearable: %#v", cfg.Network.MITM.Bypass.Hosts)
	}
	if len(cfg.Network.MITM.Bypass.SNI) != 1 || cfg.Network.MITM.Bypass.SNI[0] != "api.stripe.com" {
		t.Fatalf("MITM bypass SNI should be replaceable: %#v", cfg.Network.MITM.Bypass.SNI)
	}
	if got, want := cfg.Network.HTTP.Default, "deny"; got != want {
		t.Fatalf("HTTP default = %q, want %q", got, want)
	}
	if len(cfg.Network.HTTP.Rules) != 0 {
		t.Fatalf("HTTP rules should be clearable: %#v", cfg.Network.HTTP.Rules)
	}
}

func TestLoadMITMAndHTTPDefaults(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte("workspace:\n  target: /workspace\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.Network.MITM.Mode, "optional"; got != want {
		t.Fatalf("MITM mode default = %q, want %q", got, want)
	}
	if got, want := cfg.Network.MITM.OnUntrustedCert, "deny"; got != want {
		t.Fatalf("MITM on_untrusted_cert default = %q, want %q", got, want)
	}
	if got, want := cfg.Network.HTTP.Default, "deny"; got != want {
		t.Fatalf("HTTP default = %q, want %q", got, want)
	}
	if cfg.Network.Audit {
		t.Fatal("network audit default should be false")
	}
}

func TestLoadParsesNetworkAudit(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".config", "keel", "config.yaml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte("network:\n  audit: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Network.Audit {
		t.Fatal("network audit should be true when configured")
	}
}

func TestLoadProjectCanDisableInheritedNetworkAudit(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".config", "keel", "config.yaml"), []byte("network:\n  audit: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte("network:\n  audit: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Network.Audit {
		t.Fatal("project config should be able to disable inherited network audit")
	}
}

func TestApplyOverrides(t *testing.T) {
	cfg := Default()
	cfg.Image = "ubuntu:24.04"

	overrides := OverrideConfig{
		Image:   "alpine:3.21",
		Verbose: true,
		DryRun:  true,
		Command: []string{"/bin/sh"},
	}

	cfg = ApplyOverrides(cfg, overrides)

	if cfg.Image != "alpine:3.21" {
		t.Fatalf("cfg.Image = %q, want alpine:3.21", cfg.Image)
	}
	if !cfg.Verbose || !cfg.DryRun {
		t.Fatalf("expected verbose and dry-run to be true: %+v", cfg)
	}
	if len(cfg.Command) != 1 || cfg.Command[0] != "/bin/sh" {
		t.Fatalf("unexpected command: %#v", cfg.Command)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", path, err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
