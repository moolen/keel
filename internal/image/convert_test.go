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
