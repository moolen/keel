package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func e2eEnabled(t *testing.T) bool {
	t.Helper()
	return os.Getenv("KEEL_E2E") == "1"
}

func runDockerBuildProxyOnlyE2E(t *testing.T) error {
	t.Helper()

	requireE2EPrerequisites(t)

	repoRoot := findRepoRoot(t)
	artifacts := buildArtifacts(t, repoRoot)

	tmpHome := t.TempDir()
	projectDir := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		return err
	}

	config := strings.Builder{}
	config.WriteString("image: docker:28-dind\n")
	config.WriteString("image_cache_dir: " + filepath.Join(tmpHome, ".cache", "keel", "images") + "\n")
	hostKernelPath := filepath.Join(os.Getenv("HOME"), ".cache", "keel", "kernel", "vmlinux")
	if _, err := os.Stat(hostKernelPath); err == nil {
		config.WriteString("kernel:\n")
		config.WriteString("  path: " + hostKernelPath + "\n")
	}
	config.WriteString(`workspace:
  mount: .
  target: /workspace
features:
  - name: docker
    config:
      storage_driver: vfs
network:
  dns:
    allowed:
      - auth.docker.io
      - registry-1.docker.io
      - '*.r2.cloudflarestorage.com'
      - dl-cdn.alpinelinux.org
      - '*.docker.io'
      - '*.alpinelinux.org'
  tls:
    allowed_sni:
      - auth.docker.io
      - registry-1.docker.io
      - '*.r2.cloudflarestorage.com'
      - dl-cdn.alpinelinux.org
      - '*.docker.io'
      - '*.alpinelinux.org'
`)
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte(config.String()), 0o644); err != nil {
		return err
	}
	dockerfile := "FROM alpine:3.20\nRUN apk add --no-cache curl >/dev/null\n"
	if err := os.WriteFile(filepath.Join(projectDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return err
	}

	cmd := exec.Command(artifacts.keelPath, "--", "docker", "build", "--no-cache", "--progress=plain", ".")
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(),
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker build e2e failed: %w\n%s", err, output)
	}

	text := string(output)
	for _, want := range []string{
		"#5 [2/2] RUN apk add --no-cache curl >/dev/null",
		"#6 DONE",
		"Network summary:",
		"dl-cdn.alpinelinux.org:443 policy=allowed",
		"cloudflarestorage.com:443 policy=allowed",
	} {
		if !strings.Contains(text, want) {
			return fmt.Errorf("docker build e2e missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "policy=denied") {
		return fmt.Errorf("docker build e2e unexpectedly denied traffic\n%s", text)
	}
	return nil
}

type builtArtifacts struct {
	keelPath string
}

func buildArtifacts(t *testing.T, repoRoot string) builtArtifacts {
	t.Helper()

	outDir := t.TempDir()
	binDir := filepath.Join(outDir, "bin")
	distDir := filepath.Join(outDir, "dist")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		t.Fatal(err)
	}

	runCmd(t, repoRoot, "/usr/local/go/bin/go", "build", "-o", filepath.Join(binDir, "keel"), "./cmd/keel")
	runCmdEnv(t, filepath.Join(repoRoot, "guest"), []string{
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	}, "/usr/local/go/bin/go", "build", "-ldflags=-s -w", "-o", filepath.Join(distDir, "keel-agent"), "./cmd/keel-agent")

	return builtArtifacts{
		keelPath: filepath.Join(binDir, "keel"),
	}
}

func requireE2EPrerequisites(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("Firecracker e2e requires linux")
	}
	for _, binary := range []string{"firecracker", "mkfs.ext4", "debugfs", "iptables", "ip6tables"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("missing prerequisite %s: %v", binary, err)
		}
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skipf("/dev/kvm unavailable: %v", err)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root")
		}
		dir = parent
	}
}

func runCmd(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	runCmdEnv(t, dir, nil, name, args...)
}

func runCmdEnv(t *testing.T, dir string, extraEnv []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output.String())
	}
}
