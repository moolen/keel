package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

type KernelCacheMetadata struct {
	SourceKind   string `json:"source_kind"`
	ResolvedTag  string `json:"resolved_tag,omitempty"`
	KernelURL    string `json:"kernel_url"`
	SHA256URL    string `json:"sha256_url,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

type kernelCacheLayout struct {
	rootDir      string
	archDir      string
	kernelPath   string
	metadataPath string
}

func defaultKernelCacheDir() string {
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "keel", "kernel")
	}
	return filepath.Join(os.TempDir(), "keel", "kernel")
}

func (m KernelManager) kernelCacheDir() string {
	if m.CacheDir != "" {
		return m.CacheDir
	}
	return defaultKernelCacheDir()
}

func cacheLayoutForReleaseLatest(baseDir, arch string) kernelCacheLayout {
	return newKernelCacheLayout(filepath.Join(baseDir, "release-latest"), arch)
}

func cacheLayoutForReleaseTag(baseDir, tag, arch string) kernelCacheLayout {
	return newKernelCacheLayout(filepath.Join(baseDir, "release-"+tag), arch)
}

func cacheLayoutForURL(baseDir, sourceURL, arch string) kernelCacheLayout {
	sum := sha256.Sum256([]byte(sourceURL))
	return newKernelCacheLayout(filepath.Join(baseDir, "url-"+hex.EncodeToString(sum[:])), arch)
}

func newKernelCacheLayout(rootDir, arch string) kernelCacheLayout {
	archDir := filepath.Join(rootDir, arch)
	return kernelCacheLayout{
		rootDir:      rootDir,
		archDir:      archDir,
		kernelPath:   filepath.Join(archDir, "vmlinux"),
		metadataPath: filepath.Join(archDir, "metadata.json"),
	}
}

func (l kernelCacheLayout) hasKernel() bool {
	info, err := os.Stat(l.kernelPath)
	return err == nil && !info.IsDir()
}

func loadKernelCacheMetadata(path string) (KernelCacheMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KernelCacheMetadata{}, err
	}
	var metadata KernelCacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return KernelCacheMetadata{}, err
	}
	return metadata, nil
}

func writeKernelCacheMetadata(path string, metadata KernelCacheMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}
