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
  endpoints:
    - host: "*.github.com"
      port: 443
`)

	writeFile(t, filepath.Join(filepath.Dir(projectDir), "keel.yaml"), `
image: debian:bookworm
workspace:
  target: /src
  sync_back: true
network:
  endpoints:
    - host: api.github.com
      port: 443
      tls:
        require_sni_match: true
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
	if len(cfg.Network.Endpoints) != 1 {
		t.Fatalf("len(cfg.Network.Endpoints) = %d, want 1", len(cfg.Network.Endpoints))
	}
	if ep := cfg.Network.Endpoints[0]; ep.Host != "api.github.com" || ep.Port != 443 || ep.TLS == nil || !ep.TLS.RequireSNIMatch {
		t.Fatalf("unexpected endpoint config: %+v", ep)
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
}

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
	rule := ep.HTTP.Rules[0]
	if rule.Action != "allow" {
		t.Fatalf("endpoint HTTP rule action = %q, want allow", rule.Action)
	}
	if len(rule.Methods) != 1 || rule.Methods[0] != "GET" {
		t.Fatalf("endpoint HTTP rule methods = %+v, want [GET]", rule.Methods)
	}
	if len(rule.Paths) != 1 || rule.Paths[0] != "/repos/*" {
		t.Fatalf("endpoint HTTP rule paths = %+v, want [/repos/*]", rule.Paths)
	}
	second := cfg.Network.Endpoints[1]
	if second.Host != "objects.githubusercontent.com" || second.Port != 443 {
		t.Fatalf("second endpoint = %+v, want objects.githubusercontent.com:443", second)
	}
	if second.MITM == nil {
		t.Fatal("second endpoint MITM = nil, want required false")
	}
	if second.MITM.Required {
		t.Fatalf("second endpoint MITM required = true, want false")
	}
	if len(cfg.Network.IPRules) != 1 || cfg.Network.IPRules[0].CIDR != "10.20.0.0/16" || cfg.Network.IPRules[0].Port != 5432 {
		t.Fatalf("ip_rules = %+v", cfg.Network.IPRules)
	}
	if cfg.Network.MITM.CA.Name != "keel-local-ca" || !cfg.Network.MITM.CA.InstallSystem || !cfg.Network.MITM.CA.InstallDocker {
		t.Fatalf("MITM CA = %+v", cfg.Network.MITM.CA)
	}
}

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

func TestLoadRejectsInvalidNetworkConfig(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "endpoint missing host",
			body: "network:\n  endpoints:\n    - port: 443\n",
			want: "host",
		},
		{
			name: "endpoint invalid port",
			body: "network:\n  endpoints:\n    - host: api.github.com\n      port: 70000\n",
			want: "port",
		},
		{
			name: "endpoint http without required mitm",
			body: "network:\n  endpoints:\n    - host: api.github.com\n      port: 443\n      http:\n        default: deny\n",
			want: "mitm.required",
		},
		{
			name: "endpoint invalid http default",
			body: "network:\n  endpoints:\n    - host: api.github.com\n      port: 443\n      mitm:\n        required: true\n      http:\n        default: block\n",
			want: "allow or deny",
		},
		{
			name: "endpoint invalid http rule action",
			body: "network:\n  endpoints:\n    - host: api.github.com\n      port: 443\n      mitm:\n        required: true\n      http:\n        rules:\n          - action: block\n",
			want: "allow or deny",
		},
		{
			name: "ip rule invalid cidr",
			body: "network:\n  ip_rules:\n    - cidr: 10.20.0.0\n      port: 5432\n",
			want: "cidr",
		},
		{
			name: "ip rule invalid port",
			body: "network:\n  ip_rules:\n    - cidr: 10.20.0.0/16\n      port: 0\n",
			want: "port",
		},
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
				t.Fatal("Load() error = nil, want invalid network config rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadNetworkDefaults(t *testing.T) {
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
	if got, want := cfg.Network.Mode, "vsock"; got != want {
		t.Fatalf("network mode default = %q, want %q", got, want)
	}
	if cfg.Network.Audit {
		t.Fatal("network audit default should be false")
	}
	if got, want := cfg.Network.MITM.CA.Name, "keel-local-ca"; got != want {
		t.Fatalf("MITM CA name default = %q, want %q", got, want)
	}
	if !cfg.Network.MITM.CA.InstallSystem || !cfg.Network.MITM.CA.InstallDocker {
		t.Fatalf("MITM CA install defaults = %+v, want both true", cfg.Network.MITM.CA)
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
