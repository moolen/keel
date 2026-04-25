package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrepareWorkspaceImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for workspace image tests")
	}

	sourceDir := t.TempDir()
	writeWorkspaceFile(t, sourceDir, "README.md", "hello")
	writeWorkspaceFile(t, sourceDir, "nested/file.txt", "world")

	imagePath := filepath.Join(t.TempDir(), "workspace.ext4")
	result, err := PrepareImage(PrepareOptions{
		SourceDir:  sourceDir,
		ImagePath:  imagePath,
		SizeMB:     64,
		Label:      "workspace",
		Mountpoint: "/workspace",
	})
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}

	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", imagePath, err)
	}
	if info.Size() == 0 {
		t.Fatal("workspace image is empty")
	}
	if result.SizeBytes != info.Size() {
		t.Fatalf("result.SizeBytes = %d, want %d", result.SizeBytes, info.Size())
	}
}
