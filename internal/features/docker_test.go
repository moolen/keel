package features

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/image"
)

func TestDockerFeaturePrepareRootfsRejectsMissingBinaries(t *testing.T) {
	rootfsPath := createEmptyRootfs(t)

	err := NewDockerFeature().PrepareRootfs(rootfsPath, nil)
	if err == nil {
		t.Fatal("PrepareRootfs() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "docker feature requires") {
		t.Fatalf("PrepareRootfs() error = %v", err)
	}
}

func TestDockerFeaturePrepareRootfsAcceptsDockerImage(t *testing.T) {
	rootfsPath := createEmptyRootfs(t)
	writeFileToRootfs(t, rootfsPath, "/usr/local/bin/docker", "#!/bin/sh\n")
	writeFileToRootfs(t, rootfsPath, "/usr/local/bin/dockerd", "#!/bin/sh\n")

	if err := NewDockerFeature().PrepareRootfs(rootfsPath, nil); err != nil {
		t.Fatalf("PrepareRootfs() error = %v", err)
	}
}

func TestDockerFeatureNormalizesConfig(t *testing.T) {
	normalized, err := NewDockerFeature().NormalizeConfig(map[string]any{
		"registry_mirrors": []any{"https://mirror.example"},
	})
	if err != nil {
		t.Fatalf("NormalizeConfig() error = %v", err)
	}
	if normalized.Name != "docker" {
		t.Fatalf("NormalizeConfig() name = %q, want docker", normalized.Name)
	}
	if got := normalized.Config["storage_driver"]; got != "vfs" {
		t.Fatalf("NormalizeConfig() storage_driver = %#v, want vfs", got)
	}
	if _, ok := normalized.Config["registry_mirrors"]; !ok {
		t.Fatalf("NormalizeConfig() config = %#v, want registry_mirrors", normalized.Config)
	}
}

func createEmptyRootfs(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for docker feature tests")
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs is required for docker feature tests")
	}

	rootfsPath := filepath.Join(t.TempDir(), "rootfs.ext4")
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, ".keep"), []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := image.CreateRootfsImage(image.CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: rootfsPath,
		SizeMB:    64,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}
	return rootfsPath
}

func writeFileToRootfs(t *testing.T, rootfsPath, target, content string) {
	t.Helper()
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "file")
	if err := os.WriteFile(src, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	dir := filepath.Dir(target)
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	current := ""
	for _, part := range parts {
		current += "/" + part
		if err := debugfsCommand(rootfsPath, "mkdir "+current); err != nil {
			t.Fatalf("debugfsWrite(mkdir %s) error = %v", current, err)
		}
	}
	if err := debugfsCommand(rootfsPath, "write "+src+" "+target); err != nil {
		t.Fatalf("debugfsWrite(write %s) error = %v", target, err)
	}
}

func debugfsCommand(rootfsPath, command string) error {
	cmd := exec.CommandContext(context.Background(), "debugfs", "-w", "-R", command, rootfsPath)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "directory already exists") {
		return err
	}
	return nil
}
