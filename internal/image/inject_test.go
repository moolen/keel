package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInjectGuestAgent(t *testing.T) {
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is required for rootfs injection tests")
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for rootfs injection tests")
	}

	sourceDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourceDir, "etc"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "etc", "issue"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	rootfsPath := filepath.Join(t.TempDir(), "rootfs.ext4")
	if _, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: rootfsPath,
		SizeMB:    128,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}

	err := InjectGuestAgent(rootfsPath, GuestAgentAssets{
		Binary:     []byte("agent-binary"),
		InitScript: "#!/bin/sh\necho init\n",
	})
	if err != nil {
		t.Fatalf("InjectGuestAgent() error = %v", err)
	}

	if got := debugfsRead(t, rootfsPath, "/usr/local/bin/keel-agent"); got != "agent-binary" {
		t.Fatalf("guest agent content = %q", got)
	}
	if got := debugfsRead(t, rootfsPath, "/etc/keel/init.sh"); got != "#!/bin/sh\necho init\n" {
		t.Fatalf("init script content = %q", got)
	}
}

func TestEnsureGuestAgentRefreshesDigest(t *testing.T) {
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is required for rootfs injection tests")
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for rootfs injection tests")
	}

	sourceDir := t.TempDir()
	rootfsPath := filepath.Join(t.TempDir(), "rootfs.ext4")
	if _, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: rootfsPath,
		SizeMB:    128,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}

	digestPath := filepath.Join(t.TempDir(), "guest-agent.sha256")
	if err := os.WriteFile(digestPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	refreshed, err := EnsureGuestAgent(rootfsPath, digestPath, GuestAgentAssets{
		Binary:     []byte("agent-v2"),
		InitScript: "#!/bin/sh\nexec /usr/local/bin/keel-agent\n",
	})
	if err != nil {
		t.Fatalf("EnsureGuestAgent() error = %v", err)
	}
	if !refreshed {
		t.Fatal("expected EnsureGuestAgent to refresh stale digest")
	}
	if got := debugfsRead(t, rootfsPath, "/usr/local/bin/keel-agent"); got != "agent-v2" {
		t.Fatalf("guest agent content = %q", got)
	}
	data, err := os.ReadFile(digestPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), (GuestAgentAssets{Binary: []byte("agent-v2")}).Digest(); got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
}

func TestEnsureGuestAgentSkipsMatchingDigest(t *testing.T) {
	digestPath := filepath.Join(t.TempDir(), "guest-agent.sha256")
	assets := GuestAgentAssets{Binary: []byte("agent-same")}
	if err := os.WriteFile(digestPath, []byte(assets.Digest()+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	refreshed, err := EnsureGuestAgent(filepath.Join(t.TempDir(), "rootfs.ext4"), digestPath, assets)
	if err != nil {
		t.Fatalf("EnsureGuestAgent() error = %v", err)
	}
	if refreshed {
		t.Fatal("expected EnsureGuestAgent to skip matching digest")
	}
}

func debugfsRead(t *testing.T, imagePath, target string) string {
	t.Helper()
	cmd := exec.Command("debugfs", "-R", "cat "+target, imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("debugfs read %s error = %v: %s", target, err, output)
	}
	text := string(output)
	if lines := strings.SplitN(text, "\n", 2); len(lines) == 2 && strings.HasPrefix(lines[0], "debugfs ") {
		return lines[1]
	}
	return text
}
