package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestPullAndCacheMaterializesArtifacts(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	img := testImage(t, map[string]string{
		"etc/issue":      "keel\n",
		"usr/bin/keelsh": "#!/bin/sh\n",
	})
	cacheDir := t.TempDir()
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			return img, nil
		},
		GuestInit: func() (GuestAgentAssets, error) {
			return GuestAgentAssets{
				Binary:     []byte("agent-binary"),
				InitScript: "#!/bin/sh\nexec /usr/local/bin/keel-agent\n",
			}, nil
		},
		GuestTrust: GuestTrustAssets{
			Enabled:   true,
			CACertPEM: []byte("trust-ca"),
		},
	}

	result, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:test")
	if err != nil {
		t.Fatalf("PullAndCache() error = %v", err)
	}

	if _, err := os.Stat(result.Layout.OCIPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.OCIPath, err)
	}
	if _, err := os.Stat(result.Layout.RootfsPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.RootfsPath, err)
	}
	if _, err := os.Stat(result.Layout.AgentPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.AgentPath, err)
	}
	if got := debugfsRead(t, result.Layout.RootfsPath, "/usr/local/bin/keel-agent"); got != "agent-binary" {
		t.Fatalf("guest agent content = %q", got)
	}
	if got := debugfsRead(t, result.Layout.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); got != "trust-ca" {
		t.Fatalf("guest trust cert content = %q", got)
	}
}

func TestPullAndCacheReturnsCachedLayoutWithoutFetching(t *testing.T) {
	cacheDir := t.TempDir()
	layout, err := ResolveCacheLayout(cacheDir, "ghcr.io/moolen/keel:test")
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(layout.Directory, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	for _, item := range []struct {
		path string
		data string
	}{
		{path: layout.RootfsPath, data: "rootfs"},
		{path: layout.OCIPath, data: "oci"},
		{path: layout.AgentPath, data: "digest"},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", item.path, err)
		}
	}

	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			t.Fatal("Fetch() should not be called when cache exists")
			return nil, nil
		},
		GuestInit: func() (GuestAgentAssets, error) {
			t.Fatal("GuestInit() should not be called when cache exists")
			return GuestAgentAssets{}, nil
		},
	}

	result, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:test")
	if err != nil {
		t.Fatalf("PullAndCache() error = %v", err)
	}
	if result.Layout.Directory != layout.Directory {
		t.Fatalf("result.Layout.Directory = %q, want %q", result.Layout.Directory, layout.Directory)
	}
}

func testImage(t *testing.T, files map[string]string) v1.Image {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q) error = %v", name, err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatalf("WriteString(%q) error = %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	if err != nil {
		t.Fatalf("LayerFromReader() error = %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("AppendLayers() error = %v", err)
	}
	return img
}

func TestListCachedImages(t *testing.T) {
	cacheDir := t.TempDir()
	for _, path := range []string{
		filepath.Join(cacheDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4"),
		filepath.Join(cacheDir, "ghcr.io", "moolen", "keel", "test", "rootfs.ext4"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", path, err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	images, err := ListCachedImages(cacheDir)
	if err != nil {
		t.Fatalf("ListCachedImages() error = %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("len(images) = %d, want 2", len(images))
	}
	if images[0].Reference != "ghcr.io/moolen/keel:test" {
		t.Fatalf("images[0].Reference = %q", images[0].Reference)
	}
	if images[0].SizeBytes != 1 {
		t.Fatalf("images[0].SizeBytes = %d, want 1", images[0].SizeBytes)
	}
}

func TestDescribeRemoteImageErrorAddsAuthHint(t *testing.T) {
	err := describeRemoteImageError(errors.New("UNAUTHORIZED: authentication required"))
	if !strings.Contains(err, "docker login") {
		t.Fatalf("error = %q, want docker login hint", err)
	}
}

func TestDescribeRemoteImageErrorAddsNetworkHint(t *testing.T) {
	err := describeRemoteImageError(errors.New("dial tcp: lookup registry.example.com: no such host"))
	if !strings.Contains(err, "network connectivity") {
		t.Fatalf("error = %q, want network hint", err)
	}
}
