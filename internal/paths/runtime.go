package paths

import (
	"errors"
	"os"
	"path/filepath"
)

var (
	RuntimeDataRoot    = "/var/lib/keel/runtime"
	RuntimeControlRoot = "/var/run/keel"
)

func RuntimeTempRoot() string {
	return filepath.Join(resolveRuntimeDataRoot(), "tmp")
}

func EnsureRuntimeRoots() error {
	for _, dir := range []string{resolveRuntimeDataRoot(), resolveRuntimeControlRoot(), RuntimeTempRoot()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func NewRuntimeDataDir() (string, error) {
	if err := EnsureRuntimeRoots(); err != nil {
		return "", err
	}
	return os.MkdirTemp(resolveRuntimeDataRoot(), "vm-")
}

func NewRuntimeControlDir() (string, error) {
	if err := EnsureRuntimeRoots(); err != nil {
		return "", err
	}
	return os.MkdirTemp(resolveRuntimeControlRoot(), "vm-")
}

func NewTempDir(pattern string) (string, error) {
	if err := EnsureRuntimeRoots(); err != nil {
		return "", err
	}
	return os.MkdirTemp(RuntimeTempRoot(), pattern)
}

func resolveRuntimeDataRoot() string {
	if ensureWritableRoot(RuntimeDataRoot) == nil {
		return RuntimeDataRoot
	}
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "keel", "runtime")
	}
	return filepath.Join(os.TempDir(), "keel", "runtime")
}

func resolveRuntimeControlRoot() string {
	if ensureWritableRoot(RuntimeControlRoot) == nil {
		return RuntimeControlRoot
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		return filepath.Join(runtimeDir, "keel")
	}
	return filepath.Join(os.TempDir(), "keel-run")
}

func ensureWritableRoot(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(path, ".keel-write-test-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
