package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func e2eEnabled(t *testing.T) bool {
	t.Helper()
	return os.Getenv("KEEL_E2E") == "1"
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

func requireFreeDiskSpace(t *testing.T, path string, minBytes uint64) {
	t.Helper()

	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Skipf("could not check free space for %s: %v", path, err)
	}
	available := stat.Bavail * uint64(stat.Bsize)
	if available < minBytes {
		t.Skipf("insufficient free space on %s: have %s, need at least %s", path, formatBytes(available), formatBytes(minBytes))
	}
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return strconv.FormatUint(value, 10) + "B"
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(value)/float64(div), "KMGTPE"[exp])
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
