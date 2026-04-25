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
