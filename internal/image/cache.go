package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const CurrentCacheVersion = "2"

type CacheLayout struct {
	Registry    string
	Repository  string
	Tag         string
	Directory   string
	RootfsPath  string
	OCIPath     string
	AgentPath   string
	DigestPath  string
	VersionPath string
}

func CachePath(cacheDir, ref string) string {
	layout, err := ResolveCacheLayout(cacheDir, ref)
	if err != nil {
		return filepath.Join(cacheDir, sanitizePath(ref))
	}
	return layout.Directory
}

func ResolveCacheLayout(cacheDir, ref string) (CacheLayout, error) {
	registry, repository, version, err := parseReference(ref)
	if err != nil {
		return CacheLayout{}, err
	}

	dir := filepath.Join(cacheDir, registry, filepath.FromSlash(repository), version)
	return CacheLayout{
		Registry:    registry,
		Repository:  repository,
		Tag:         version,
		Directory:   dir,
		RootfsPath:  filepath.Join(dir, "rootfs.ext4"),
		OCIPath:     filepath.Join(dir, "image.tar"),
		AgentPath:   filepath.Join(dir, "guest-agent.sha256"),
		DigestPath:  filepath.Join(dir, "image.digest"),
		VersionPath: filepath.Join(dir, "cache.version"),
	}, nil
}

func CacheReady(layout CacheLayout, requireAgent bool) (bool, error) {
	required := []string{layout.RootfsPath, layout.OCIPath, layout.VersionPath}
	if requireAgent {
		required = append(required, layout.AgentPath)
	}
	for _, path := range required {
		info, err := os.Stat(path)
		if err != nil {
			return false, nil //nolint:nilerr // treat any stat error as cache miss
		}
		if info.IsDir() {
			return false, nil
		}
	}
	data, err := os.ReadFile(layout.VersionPath)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == CurrentCacheVersion, nil
}

func WriteCacheVersion(path string) error {
	if path == "" {
		return fmt.Errorf("cache version path is required")
	}
	return os.WriteFile(path, []byte(CurrentCacheVersion+"\n"), 0o644)
}

func parseReference(ref string) (registry, repository, version string, err error) {
	if ref == "" {
		return "", "", "", fmt.Errorf("empty image reference")
	}

	if strings.Contains(ref, "@") {
		parts := strings.SplitN(ref, "@", 2)
		registry, repository = normalizeRegistry(parts[0])
		if registry == "" || repository == "" {
			return "", "", "", fmt.Errorf("invalid image reference %q", ref)
		}
		return registry, repository, sanitizePath(strings.ReplaceAll(parts[1], ":", "-")), nil
	}

	tag := "latest"
	image := ref
	if slash := strings.LastIndex(image, "/"); slash >= 0 {
		if colon := strings.LastIndex(image, ":"); colon > slash {
			tag = image[colon+1:]
			image = image[:colon]
		}
	} else if colon := strings.LastIndex(image, ":"); colon >= 0 {
		tag = image[colon+1:]
		image = image[:colon]
	}

	registry, repository = normalizeRegistry(image)
	if registry == "" || repository == "" {
		return "", "", "", fmt.Errorf("invalid image reference %q", ref)
	}
	return registry, repository, sanitizePath(tag), nil
}

func normalizeRegistry(image string) (registry, repository string) {
	parts := strings.Split(image, "/")
	switch {
	case len(parts) == 1:
		return "index.docker.io", "library/" + parts[0]
	case looksLikeRegistry(parts[0]):
		return parts[0], strings.Join(parts[1:], "/")
	default:
		return "index.docker.io", image
	}
}

func looksLikeRegistry(part string) bool {
	return strings.Contains(part, ".") || strings.Contains(part, ":") || part == "localhost"
}

func sanitizePath(value string) string {
	replacer := strings.NewReplacer("/", "-", "@", "-", ":", "-", "\\", "-")
	return replacer.Replace(value)
}

func referenceUsesDigest(ref string) bool {
	return strings.Contains(ref, "@")
}
