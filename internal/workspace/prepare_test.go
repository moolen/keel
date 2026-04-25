package workspace

import (
	"net"
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

func TestPrepareWorkspaceImageSkipsSockets(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for workspace image tests")
	}

	sourceDir := t.TempDir()
	socketPath := filepath.Join(sourceDir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer listener.Close()

	imagePath := filepath.Join(t.TempDir(), "workspace.ext4")
	if _, err := PrepareImage(PrepareOptions{
		SourceDir:  sourceDir,
		ImagePath:  imagePath,
		SizeMB:     64,
		Label:      "workspace",
		Mountpoint: "/workspace",
	}); err != nil {
		t.Fatalf("PrepareImage() error with socket in tree = %v", err)
	}
}

func TestSnapshotDirectoryCopiesRegularFilesAndSymlinks(t *testing.T) {
	sourceDir := t.TempDir()
	writeWorkspaceFile(t, sourceDir, "nested/file.txt", "hello")
	if err := os.Symlink("nested/file.txt", filepath.Join(sourceDir, "file.link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	stageDir, err := snapshotDirectory(sourceDir)
	if err != nil {
		t.Fatalf("snapshotDirectory() error = %v", err)
	}
	defer os.RemoveAll(stageDir)

	data, err := os.ReadFile(filepath.Join(stageDir, "nested", "file.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("staged file = %q, want hello", string(data))
	}
	linkTarget, err := os.Readlink(filepath.Join(stageDir, "file.link"))
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if linkTarget != "nested/file.txt" {
		t.Fatalf("link target = %q, want nested/file.txt", linkTarget)
	}
}
