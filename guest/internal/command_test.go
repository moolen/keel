package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCommandPathUsesProvidedEnvPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	resolved, err := resolveCommandPath("docker", []string{"PATH=" + dir})
	if err != nil {
		t.Fatalf("resolveCommandPath() error = %v", err)
	}
	if resolved != path {
		t.Fatalf("resolved path = %q, want %q", resolved, path)
	}
}

func TestResolveCommandPathLeavesAbsolutePathsUntouched(t *testing.T) {
	resolved, err := resolveCommandPath("/bin/sh", nil)
	if err != nil {
		t.Fatalf("resolveCommandPath() error = %v", err)
	}
	if resolved != "/bin/sh" {
		t.Fatalf("resolved path = %q, want /bin/sh", resolved)
	}
}
