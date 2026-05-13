package workspace

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncDirectoriesAppliesConfirmedChanges(t *testing.T) {
	hostDir := t.TempDir()
	vmDir := t.TempDir()

	writeWorkspaceFile(t, hostDir, "modified.txt", "before")
	writeWorkspaceFile(t, hostDir, "deleted.txt", "remove me")
	writeWorkspaceFile(t, vmDir, "modified.txt", "after")
	writeWorkspaceFile(t, vmDir, "added.txt", "new file")

	var output bytes.Buffer
	result, err := SyncDirectories(SyncOptions{
		HostDir:     hostDir,
		VMDir:       vmDir,
		SyncDeletes: true,
		Confirm:     true,
		In:          strings.NewReader("y\n"),
		Out:         &output,
	})
	if err != nil {
		t.Fatalf("SyncDirectories() error = %v", err)
	}
	if !result.Applied {
		t.Fatal("expected sync to apply changes")
	}
	assertWorkspaceFile(t, hostDir, "modified.txt", "after")
	assertWorkspaceFile(t, hostDir, "added.txt", "new file")
	assertWorkspaceMissing(t, hostDir, "deleted.txt")
	if !strings.Contains(output.String(), "Workspace changes detected") {
		t.Fatalf("output = %q, want diff summary", output.String())
	}
}

func TestSyncDirectoriesShowsDetailedDiffAndSkipsByDefault(t *testing.T) {
	hostDir := t.TempDir()
	vmDir := t.TempDir()

	writeWorkspaceFile(t, hostDir, "modified.txt", "before")
	writeWorkspaceFile(t, vmDir, "modified.txt", "after")

	var output bytes.Buffer
	result, err := SyncDirectories(SyncOptions{
		HostDir: hostDir,
		VMDir:   vmDir,
		Confirm: true,
		In:      strings.NewReader("d\nn\n"),
		Out:     &output,
	})
	if err != nil {
		t.Fatalf("SyncDirectories() error = %v", err)
	}
	if result.Applied {
		t.Fatal("expected sync to be skipped")
	}
	assertWorkspaceFile(t, hostDir, "modified.txt", "before")
	if !strings.Contains(output.String(), "M modified.txt") {
		t.Fatalf("output = %q, want detailed diff entry", output.String())
	}
}

func TestSyncDirectoriesLeavesDeletedFilesWhenDisabled(t *testing.T) {
	hostDir := t.TempDir()
	vmDir := t.TempDir()

	writeWorkspaceFile(t, hostDir, "deleted.txt", "keep me")

	result, err := SyncDirectories(SyncOptions{
		HostDir:     hostDir,
		VMDir:       vmDir,
		SyncDeletes: false,
		Confirm:     false,
	})
	if err != nil {
		t.Fatalf("SyncDirectories() error = %v", err)
	}
	if !result.Applied {
		t.Fatal("expected sync to apply additions/modifications")
	}
	assertWorkspaceFile(t, hostDir, "deleted.txt", "keep me")
}

func TestSyncImageAppliesChangesFromWorkspaceImage(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for sync image tests")
	}
	if err := exec.CommandContext(context.Background(), "sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo is required for sync image tests")
	}

	hostDir := t.TempDir()
	vmDir := t.TempDir()
	writeWorkspaceFile(t, hostDir, "modified.txt", "before")
	writeWorkspaceFile(t, hostDir, "deleted.txt", "remove me")
	writeWorkspaceFile(t, vmDir, "modified.txt", "after")
	writeWorkspaceFile(t, vmDir, "added.txt", "new file")

	imagePath := filepath.Join(t.TempDir(), "workspace.ext4")
	if _, err := PrepareImage(PrepareOptions{
		SourceDir: vmDir,
		ImagePath: imagePath,
		SizeMB:    64,
		Label:     "workspace",
	}); err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}

	result, err := SyncImage(ImageSyncOptions{
		HostDir:     hostDir,
		ImagePath:   imagePath,
		SyncDeletes: true,
		Confirm:     false,
	})
	if err != nil {
		t.Fatalf("SyncImage() error = %v", err)
	}
	if !result.Applied {
		t.Fatal("expected sync to apply changes")
	}
	assertWorkspaceFile(t, hostDir, "modified.txt", "after")
	assertWorkspaceFile(t, hostDir, "added.txt", "new file")
	assertWorkspaceMissing(t, hostDir, "deleted.txt")
}

func assertWorkspaceFile(t *testing.T, root, rel, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", rel, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", rel, string(data), want)
	}
}

func assertWorkspaceMissing(t *testing.T, root, rel string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
		t.Fatalf("%s should not exist", rel)
	}
}
