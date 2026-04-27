package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigUsesReleaseManagedKernelSource(t *testing.T) {
	cfg := Default()

	if got, want := cfg.Kernel.Source, "release://latest"; got != want {
		t.Fatalf("cfg.Kernel.Source = %q, want %q", got, want)
	}
}

func TestLoadConfigReadsKernelSource(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keel.yaml")
	if err := os.WriteFile(configPath, []byte("kernel:\n  source: release://v0.2.0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: dir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.Kernel.Source, "release://v0.2.0"; got != want {
		t.Fatalf("cfg.Kernel.Source = %q, want %q", got, want)
	}
}

func TestLoadMergedConfig(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	globalDir := filepath.Join(homeDir, ".config", "keel")
	projectDir := filepath.Join(t.TempDir(), "project", "nested")

	mkdirAll(t, globalDir)
	mkdirAll(t, projectDir)

	writeFile(t, filepath.Join(globalDir, "config.yaml"), `
image_cache_dir: ~/.cache/custom-keel/images
kernel:
  path: /opt/keel/vmlinux
resources:
  vcpu: 3
  memory_mb: 3072
  disk_mb: 6144
  root_disk_mb: 8192
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
  static:
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
	if cfg.Kernel.Source != "" {
		t.Fatalf("cfg.Kernel.Source = %q, want empty when kernel.path is set", cfg.Kernel.Source)
	}
	if cfg.Resources.VCPU != 3 || cfg.Resources.MemoryMB != 3072 || cfg.Resources.DiskMB != 6144 || cfg.Resources.RootDiskMB != 8192 {
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
	if cfg.Env.Static["CI"] != "1" || cfg.Env.Static["TERM"] != "xterm-256color" {
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

func TestLoadProjectWorkspaceBooleansCanDisableDefaults(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	mkdirAll(t, filepath.Join(tmpHome, ".config", "keel"))
	writeFile(t, filepath.Join(projectDir, "keel.yaml"), `
workspace:
  mount: .
  sync_back: false
  sync_deletes: false
  sync_confirm: false
network:
  deny_if_no_sni: false
`)

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Workspace.SyncBack {
		t.Fatalf("cfg.Workspace.SyncBack = true, want false")
	}
	if cfg.Workspace.SyncDeletes {
		t.Fatalf("cfg.Workspace.SyncDeletes = true, want false")
	}
	if cfg.Workspace.SyncConfirm {
		t.Fatalf("cfg.Workspace.SyncConfirm = true, want false")
	}
	if cfg.Network.DenyIfNoSNI {
		t.Fatalf("cfg.Network.DenyIfNoSNI = true, want false")
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

func TestLoadLeavesProcessConfigOmittedByDefault(t *testing.T) {
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
	if cfg.Process != nil {
		t.Fatalf("cfg.Process = %#v, want nil", cfg.Process)
	}
}

func TestLoadParsesProcessConfig(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(`
process:
  uid: 1000
  gid: 1001
  supplementary_gids: [27, 44]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Process == nil {
		t.Fatal("cfg.Process = nil, want non-nil")
	}
	if got, want := cfg.Process.UID, 1000; got != want {
		t.Fatalf("cfg.Process.UID = %d, want %d", got, want)
	}
	if got, want := cfg.Process.GID, 1001; got != want {
		t.Fatalf("cfg.Process.GID = %d, want %d", got, want)
	}
	if got, want := cfg.Process.SupplementaryGIDs, []int{27, 44}; !equalIntSlice(got, want) {
		t.Fatalf("cfg.Process.SupplementaryGIDs = %#v, want %#v", got, want)
	}
}

func TestLoadRejectsInvalidProcessConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing gid",
			yaml: "process:\n  uid: 1000\n",
			want: "gid",
		},
		{
			name: "missing uid",
			yaml: "process:\n  gid: 1000\n",
			want: "uid",
		},
		{
			name: "supplementary gids without uid gid",
			yaml: "process:\n  supplementary_gids: [27]\n",
			want: "supplementary_gids",
		},
		{
			name: "negative uid",
			yaml: "process:\n  uid: -1\n  gid: 1000\n",
			want: "uid",
		},
		{
			name: "negative supplementary gid",
			yaml: "process:\n  uid: 1000\n  gid: 1000\n  supplementary_gids: [-1]\n",
			want: "supplementary_gids",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpHome := t.TempDir()
			projectDir := t.TempDir()
			t.Setenv("HOME", tmpHome)

			if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Load(LoadOptions{WorkingDir: projectDir})
			if err == nil {
				t.Fatal("Load() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadParsesStructuredEnvAndVolumes(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	volumeDir := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(`
process:
  uid: 1000
  gid: 1000
volumes:
  - source: `+volumeDir+`
    target: /cache
    ownership: process
env:
  static:
    CI: "1"
  from_host:
    TOKEN: HOST_TOKEN
  from_command:
    BUILD_SHA:
      command: ["sh", "-lc", "printf abc123\\n"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_TOKEN", "secret")

	cfg, err := Load(LoadOptions{WorkingDir: projectDir})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.Env.Static["CI"], "1"; got != want {
		t.Fatalf("cfg.Env.Static[CI] = %q, want %q", got, want)
	}
	if got, want := cfg.Env.FromHost["TOKEN"], "HOST_TOKEN"; got != want {
		t.Fatalf("cfg.Env.FromHost[TOKEN] = %q, want %q", got, want)
	}
	if got, want := cfg.Volumes[0].Target, "/cache"; got != want {
		t.Fatalf("cfg.Volumes[0].Target = %q, want %q", got, want)
	}
}

func TestLoadRejectsInvalidVolumeAndEnvCommandConfig(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "relative target",
			yaml: "volumes:\n  - source: " + projectDir + "\n    target: cache\n",
			want: "absolute",
		},
		{
			name: "read only sync back",
			yaml: "volumes:\n  - source: " + projectDir + "\n    target: /cache\n    read_only: true\n    sync_back: true\n",
			want: "sync_back",
		},
		{
			name: "invalid command resolver",
			yaml: "env:\n  from_command:\n    BAD:\n      command: [\"echo\", \"x\"]\n      shell: \"echo x\"\n",
			want: "must not set both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(LoadOptions{WorkingDir: projectDir})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want substring %q", err, tt.want)
			}
		})
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

func equalIntSlice(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
