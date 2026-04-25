package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiffDirectories(t *testing.T) {
	hostDir := t.TempDir()
	vmDir := t.TempDir()

	writeWorkspaceFile(t, hostDir, "same.txt", "same")
	writeWorkspaceFile(t, hostDir, "modified.txt", "before")
	writeWorkspaceFile(t, hostDir, "deleted.txt", "remove me")

	writeWorkspaceFile(t, vmDir, "same.txt", "same")
	writeWorkspaceFile(t, vmDir, "modified.txt", "after")
	writeWorkspaceFile(t, vmDir, "added.txt", "new file")

	diff, err := DiffDirectories(hostDir, vmDir)
	if err != nil {
		t.Fatalf("DiffDirectories() error = %v", err)
	}

	if got, want := diff.Added[0].Path, "added.txt"; got != want {
		t.Fatalf("added[0] = %q, want %q", got, want)
	}
	if got, want := diff.Modified[0].Path, "modified.txt"; got != want {
		t.Fatalf("modified[0] = %q, want %q", got, want)
	}
	if got, want := diff.Deleted[0].Path, "deleted.txt"; got != want {
		t.Fatalf("deleted[0] = %q, want %q", got, want)
	}
}

func writeWorkspaceFile(t *testing.T, root, rel, data string) {
	t.Helper()
	path := filepath.Join(root, rel)
	mkdirAll(t, filepath.Dir(path))
	writeFile(t, path, data)
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", path, err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
