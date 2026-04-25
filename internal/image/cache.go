package image

import (
	"fmt"
	"path/filepath"
	"strings"
)

type CacheLayout struct {
	Registry   string
	Repository string
	Tag        string
	Directory  string
	RootfsPath string
	OCIPath    string
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
		Registry:   registry,
		Repository: repository,
		Tag:        version,
		Directory:  dir,
		RootfsPath: filepath.Join(dir, "rootfs.ext4"),
		OCIPath:    filepath.Join(dir, "image.tar"),
	}, nil
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
