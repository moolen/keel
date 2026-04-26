package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func LoadBootManifest(device string) (pkgboot.Manifest, error) {
	if device == "" {
		return pkgboot.Manifest{}, os.ErrNotExist
	}
	mountDir := "/run/keel-meta"
	if err := os.MkdirAll(mountDir, 0o755); err != nil {
		return pkgboot.Manifest{}, err
	}
	var lastErr error
	for range 50 {
		if _, err := os.Stat(device); err == nil {
			lastErr = syscall.Mount(device, mountDir, "ext4", syscall.MS_RDONLY, "")
			if lastErr == nil || lastErr == syscall.EBUSY {
				data, err := os.ReadFile(filepath.Join(mountDir, "boot.json"))
				if err != nil {
					return pkgboot.Manifest{}, err
				}
				var manifest pkgboot.Manifest
				if err := json.Unmarshal(data, &manifest); err != nil {
					return pkgboot.Manifest{}, err
				}
				return manifest, nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return pkgboot.Manifest{}, lastErr
}

func EnvListFromMap(values map[string]string, fallback []string) []string {
	if len(values) == 0 {
		return append([]string(nil), fallback...)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}
