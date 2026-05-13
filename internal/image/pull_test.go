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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if _, err := os.Stat(result.Layout.DigestPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.DigestPath, err)
	}
	if _, err := os.Stat(result.Layout.VersionPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.VersionPath, err)
	}
	if got := debugfsRead(t, result.Layout.RootfsPath, "/usr/local/bin/keel-agent"); got != "agent-binary" {
		t.Fatalf("guest agent content = %q", got)
	}
	if got := debugfsRead(t, result.Layout.RootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt"); got != "trust-ca" {
		t.Fatalf("guest trust cert content = %q", got)
	}
}

func TestPullAndCacheReportsProgress(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	img := testImage(t, map[string]string{
		"etc/issue": strings.Repeat("keel\n", 64),
	})
	cacheDir := t.TempDir()
	var updates []PullProgress
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			return img, nil
		},
		Progress: func(update PullProgress) {
			updates = append(updates, update)
		},
	}

	if _, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:test"); err != nil {
		t.Fatalf("PullAndCache() error = %v", err)
	}

	if len(updates) == 0 {
		t.Fatal("expected pull progress updates, got none")
	}
	if updates[0].Phase != PullPhaseResolve {
		t.Fatalf("first phase = %q, want %q", updates[0].Phase, PullPhaseResolve)
	}
	if !containsPullPhase(updates, PullPhaseDownload) {
		t.Fatalf("updates = %#v, want download progress", updates)
	}
	if !containsPullPhase(updates, PullPhaseExtract) {
		t.Fatalf("updates = %#v, want extract progress", updates)
	}
	if !containsPullPhase(updates, PullPhaseBuildRootfs) {
		t.Fatalf("updates = %#v, want rootfs build progress", updates)
	}
	if updates[len(updates)-1].Phase != PullPhaseReady {
		t.Fatalf("last phase = %q, want %q", updates[len(updates)-1].Phase, PullPhaseReady)
	}
}

func TestPullAndCacheWithoutProgressDoesNotBlockImageWrite(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	files := make(map[string]string)
	for i := 0; i < 48; i++ {
		files[filepath.Join("var/lib/test", strconv.Itoa(i))] = strings.Repeat("keel\n", 8)
	}
	img := testImage(t, files)
	cacheDir := t.TempDir()
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			return img, nil
		},
	}

	done := make(chan error, 1)
	go func() {
		_, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:test")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("PullAndCache() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("PullAndCache() blocked without progress receiver")
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
		{path: layout.DigestPath, data: "sha256:current"},
		{path: layout.VersionPath, data: CurrentCacheVersion + "\n"},
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

func TestPullAndCacheStoresComparableMutableTagDigest(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	img := testImage(t, map[string]string{"etc/issue": "keel\n"})
	cacheDir := t.TempDir()
	fetchCalls := 0
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			fetchCalls++
			return img, nil
		},
		ResolveDigest: func(context.Context, string) (string, error) {
			return "sha256:remote-index", nil
		},
	}

	first, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("first PullAndCache() error = %v", err)
	}
	before, err := os.Stat(first.Layout.RootfsPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", first.Layout.RootfsPath, err)
	}

	second, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("second PullAndCache() error = %v", err)
	}
	after, err := os.Stat(second.Layout.RootfsPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", second.Layout.RootfsPath, err)
	}
	if fetchCalls != 1 {
		t.Fatalf("fetchCalls = %d, want 1", fetchCalls)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("cached rootfs was rewritten: before=%s after=%s", before.ModTime(), after.ModTime())
	}
	if data, err := os.ReadFile(second.Layout.DigestPath); err != nil {
		t.Fatalf("ReadFile(%q) error = %v", second.Layout.DigestPath, err)
	} else if strings.TrimSpace(string(data)) != "sha256:remote-index" {
		t.Fatalf("digest metadata = %q, want remote digest", strings.TrimSpace(string(data)))
	}
}

func TestPullAndCacheRebuildsLegacyCacheFromCachedOCI(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	img := testImage(t, map[string]string{"etc/issue": "fresh\n"})
	cacheDir := t.TempDir()
	initialPuller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			return img, nil
		},
	}
	result, err := initialPuller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("initial PullAndCache() error = %v", err)
	}
	if err := os.Remove(result.Layout.VersionPath); err != nil {
		t.Fatalf("Remove(%q) error = %v", result.Layout.VersionPath, err)
	}
	if err := os.WriteFile(result.Layout.RootfsPath, []byte("stale-rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", result.Layout.RootfsPath, err)
	}

	rebuildPuller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			t.Fatal("Fetch() should not be called when cached OCI tarball can rebuild the rootfs")
			return nil, nil
		},
		ResolveDigest: func(context.Context, string) (string, error) {
			data, err := os.ReadFile(result.Layout.DigestPath)
			if err != nil {
				t.Fatalf("ReadFile(%q) error = %v", result.Layout.DigestPath, err)
			}
			return strings.TrimSpace(string(data)), nil
		},
	}

	rebuilt, err := rebuildPuller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("rebuild PullAndCache() error = %v", err)
	}
	if got := debugfsRead(t, rebuilt.Layout.RootfsPath, "/etc/issue"); got != "fresh\n" {
		t.Fatalf("rebuilt rootfs content = %q", got)
	}
	if data, err := os.ReadFile(rebuilt.Layout.VersionPath); err != nil {
		t.Fatalf("ReadFile(%q) error = %v", rebuilt.Layout.VersionPath, err)
	} else if strings.TrimSpace(string(data)) != CurrentCacheVersion {
		t.Fatalf("cache version = %q, want %q", strings.TrimSpace(string(data)), CurrentCacheVersion)
	}
}

func TestPullAndCacheRefreshesMutableTagWhenDigestChanges(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	cacheDir := t.TempDir()
	layout, err := ResolveCacheLayout(cacheDir, "ghcr.io/moolen/keel:main")
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
		{path: layout.RootfsPath, data: "stale-rootfs"},
		{path: layout.OCIPath, data: "stale-oci"},
		{path: layout.AgentPath, data: "stale-agent"},
		{path: layout.DigestPath, data: "sha256:stale"},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", item.path, err)
		}
	}

	img := testImage(t, map[string]string{"etc/issue": "fresh\n"})
	fetchCalls := 0
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			fetchCalls++
			return img, nil
		},
		ResolveDigest: func(context.Context, string) (string, error) {
			return "sha256:fresh", nil
		},
	}

	result, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("PullAndCache() error = %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("fetchCalls = %d, want 1", fetchCalls)
	}
	if got := debugfsRead(t, result.Layout.RootfsPath, "/etc/issue"); got != "fresh\n" {
		t.Fatalf("rootfs content = %q", got)
	}
}

func TestPullAndCacheRefreshesMutableTagWithoutDigestMetadata(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for pull tests")
	}

	cacheDir := t.TempDir()
	layout, err := ResolveCacheLayout(cacheDir, "ghcr.io/moolen/keel:main")
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
		{path: layout.RootfsPath, data: "stale-rootfs"},
		{path: layout.OCIPath, data: "stale-oci"},
		{path: layout.AgentPath, data: "stale-agent"},
	} {
		if err := os.WriteFile(item.path, []byte(item.data), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", item.path, err)
		}
	}

	img := testImage(t, map[string]string{"etc/issue": "fresh\n"})
	fetchCalls := 0
	puller := Puller{
		Fetch: func(context.Context, string) (v1.Image, error) {
			fetchCalls++
			return img, nil
		},
		ResolveDigest: func(context.Context, string) (string, error) {
			return "sha256:fresh", nil
		},
	}

	result, err := puller.PullAndCache(context.Background(), cacheDir, "ghcr.io/moolen/keel:main")
	if err != nil {
		t.Fatalf("PullAndCache() error = %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("fetchCalls = %d, want 1", fetchCalls)
	}
	if _, err := os.Stat(result.Layout.DigestPath); err != nil {
		t.Fatalf("Stat(%q) error = %v", result.Layout.DigestPath, err)
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

func TestExtractFilesystemHandlesReadOnlyDirectories(t *testing.T) {
	tarData := newTarArchive(t, []tarEntry{
		{name: "home/", mode: 0o755, kind: tar.TypeDir},
		{name: "home/agent/", mode: 0o755, kind: tar.TypeDir},
		{name: "home/agent/go/", mode: 0o755, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/", mode: 0o755, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/mod/", mode: 0o555, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/mod/golang.org/", mode: 0o555, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/mod/golang.org/x/", mode: 0o555, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/mod/golang.org/x/mod@v0.35.0/", mode: 0o555, kind: tar.TypeDir},
		{name: "home/agent/go/pkg/mod/golang.org/x/mod@v0.35.0/LICENSE", mode: 0o444, body: "license\n", kind: tar.TypeReg},
	})

	dst := t.TempDir()
	t.Cleanup(func() {
		_ = makeTreeWritable(dst)
	})
	if err := extractFilesystem(io.NopCloser(bytes.NewReader(tarData)), dst); err != nil {
		t.Fatalf("extractFilesystem() error = %v", err)
	}

	licensePath := filepath.Join(dst, "home/agent/go/pkg/mod/golang.org/x/mod@v0.35.0/LICENSE")
	if got, err := os.ReadFile(licensePath); err != nil {
		t.Fatalf("ReadFile(%q) error = %v", licensePath, err)
	} else if string(got) != "license\n" {
		t.Fatalf("license content = %q", string(got))
	}

	modDir := filepath.Join(dst, "home/agent/go/pkg/mod")
	info, err := os.Stat(modDir)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", modDir, err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o555); got != want {
		t.Fatalf("mode(%q) = %o, want %o", modDir, got, want)
	}
}

func makeTreeWritable(root string) error {
	var paths []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(paths, func(i, j int) bool {
		return len(paths[i]) > len(paths[j])
	})
	for _, path := range paths {
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

type tarEntry struct {
	name string
	body string
	mode int64
	kind byte
}

func newTarArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Typeflag: entry.kind,
		}
		if entry.kind == tar.TypeReg {
			hdr.Size = int64(len(entry.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q) error = %v", entry.name, err)
		}
		if entry.kind == tar.TypeReg {
			if _, err := io.WriteString(tw, entry.body); err != nil {
				t.Fatalf("WriteString(%q) error = %v", entry.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return buf.Bytes()
}

func containsPullPhase(updates []PullProgress, phase PullPhase) bool {
	for _, update := range updates {
		if update.Phase == phase {
			return true
		}
	}
	return false
}
