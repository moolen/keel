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
