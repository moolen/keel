package bootmanifest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func TestWriteImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required")
	}
	imagePath := filepath.Join(t.TempDir(), "boot.ext4")
	err := WriteImage(imagePath, pkgboot.Manifest{
		Command: []string{"/bin/sh"},
		Env: map[string]string{
			"TERM": "xterm-256color",
		},
	})
	if err != nil {
		t.Fatalf("WriteImage() error = %v", err)
	}
	if _, err := os.Stat(imagePath); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
}
