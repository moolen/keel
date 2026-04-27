package image

import (
	"path/filepath"
	"testing"
)

func TestCacheLayoutFromReference(t *testing.T) {
	layout, err := ResolveCacheLayout("/var/cache/keel/images", "ubuntu:24.04")
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}

	if got, want := layout.Registry, "index.docker.io"; got != want {
		t.Fatalf("layout.Registry = %q, want %q", got, want)
	}
	if got, want := layout.Repository, "library/ubuntu"; got != want {
		t.Fatalf("layout.Repository = %q, want %q", got, want)
	}
	if got, want := layout.Tag, "24.04"; got != want {
		t.Fatalf("layout.Tag = %q, want %q", got, want)
	}
	if got, want := layout.RootfsPath, filepath.Join("/var/cache/keel/images", "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4"); got != want {
		t.Fatalf("layout.RootfsPath = %q, want %q", got, want)
	}
	if got, want := layout.AgentPath, filepath.Join("/var/cache/keel/images", "index.docker.io", "library", "ubuntu", "24.04", "guest-agent.sha256"); got != want {
		t.Fatalf("layout.AgentPath = %q, want %q", got, want)
	}
	if got, want := layout.DigestPath, filepath.Join("/var/cache/keel/images", "index.docker.io", "library", "ubuntu", "24.04", "image.digest"); got != want {
		t.Fatalf("layout.DigestPath = %q, want %q", got, want)
	}
}

func TestCacheLayoutDigestReference(t *testing.T) {
	layout, err := ResolveCacheLayout("/var/cache/keel/images", "ghcr.io/moolen/keel@sha256:deadbeef")
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}

	if got, want := layout.Tag, "sha256-deadbeef"; got != want {
		t.Fatalf("layout.Tag = %q, want %q", got, want)
	}
}
