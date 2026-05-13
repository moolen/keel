package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCreateRootfsImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for image conversion tests")
	}

	sourceDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourceDir, "etc"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "etc", "issue"), []byte("keel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	imagePath := filepath.Join(t.TempDir(), "rootfs.ext4")
	result, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: imagePath,
		SizeMB:    128,
	})
	if err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}

	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", imagePath, err)
	}
	if result.SizeBytes != info.Size() {
		t.Fatalf("result.SizeBytes = %d, want %d", result.SizeBytes, info.Size())
	}
}

func TestCreateRootfsImageHandlesFilesUnderReadOnlyDirectories(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for image conversion tests")
	}

	sourceDir := t.TempDir()
	readOnlyDir := filepath.Join(sourceDir, "usr", "share", "readonly")
	if err := os.MkdirAll(readOnlyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(readOnlyDir, "payload.txt"), []byte("keel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatalf("Chmod(read-only) error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(readOnlyDir, 0o755)
	})

	imagePath := filepath.Join(t.TempDir(), "rootfs.ext4")
	if _, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: sourceDir,
		ImagePath: imagePath,
		SizeMB:    128,
	}); err != nil {
		t.Fatalf("CreateRootfsImage() error = %v", err)
	}
}

func TestEstimateRootfsSizeMBAddsHeadroomForLargeImages(t *testing.T) {
	sourceDir := t.TempDir()
	largeFile := filepath.Join(sourceDir, "payload.bin")
	if err := os.WriteFile(largeFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Truncate(largeFile, 1900*1024*1024); err != nil {
		t.Fatalf("Truncate() error = %v", err)
	}

	sizeMB, err := estimateRootfsSizeMB(sourceDir)
	if err != nil {
		t.Fatalf("estimateRootfsSizeMB() error = %v", err)
	}
	if sizeMB <= 2048 {
		t.Fatalf("estimateRootfsSizeMB() = %d, want > 2048", sizeMB)
	}
}
