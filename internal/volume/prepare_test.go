package volume

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrepareDirectoryVolumeImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required")
	}
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "data.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareImage(PrepareOptions{
		SourcePath: sourceDir,
		ImagePath:  filepath.Join(t.TempDir(), "dir.ext4"),
		SizeMB:     64,
		Label:      "vol",
	})
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}
	if got, want := result.Kind, "dir"; got != want {
		t.Fatalf("result.Kind = %q, want %q", got, want)
	}
}

func TestPrepareFileVolumeImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required")
	}
	sourceFile := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(sourceFile, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareImage(PrepareOptions{
		SourcePath: sourceFile,
		ImagePath:  filepath.Join(t.TempDir(), "file.ext4"),
		SizeMB:     64,
		Label:      "vol",
	})
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}
	if got, want := result.Kind, "file"; got != want {
		t.Fatalf("result.Kind = %q, want %q", got, want)
	}
	if got, want := result.Subpath, filePayloadName; got != want {
		t.Fatalf("result.Subpath = %q, want %q", got, want)
	}
}
