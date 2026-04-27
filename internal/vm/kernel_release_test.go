package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
)

func TestKernelManagerEnsureReleaseSources(t *testing.T) {
	const arch = "x86_64"

	cases := []struct {
		name   string
		source string
		setup  func(t *testing.T, cacheDir string, api *releaseAPIFixture)
		assert func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture)
	}{
		{
			name:   "release://latest cache miss",
			source: "release://latest",
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err != nil {
					t.Fatalf("EnsureConfig() error = %v", err)
				}
				wantPath := filepath.Join(cacheDir, "release-latest", arch, "vmlinux")
				if path != wantPath {
					t.Fatalf("EnsureConfig() path = %q, want %q", path, wantPath)
				}
				assertFileContents(t, path, api.kernelBodies["v0.2.0"])
				meta := readKernelMetadata(t, filepath.Join(cacheDir, "release-latest", arch, "metadata.json"))
				if meta.ResolvedTag != "v0.2.0" {
					t.Fatalf("metadata ResolvedTag = %q, want v0.2.0", meta.ResolvedTag)
				}
				if api.hits["latest"] != 1 {
					t.Fatalf("latest release lookups = %d, want 1", api.hits["latest"])
				}
				if api.hits["asset:v0.2.0"] != 1 {
					t.Fatalf("kernel asset downloads = %d, want 1", api.hits["asset:v0.2.0"])
				}
				if api.hits["sha:v0.2.0"] != 1 {
					t.Fatalf("checksum downloads = %d, want 1", api.hits["sha:v0.2.0"])
				}
			},
		},
		{
			name:   "release://latest cache hit",
			source: "release://latest",
			setup: func(t *testing.T, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				writeCachedKernel(t, filepath.Join(cacheDir, "release-latest", arch), "cached-kernel", KernelCacheMetadata{
					SourceKind:  "release-latest",
					ResolvedTag: "v0.2.0",
					KernelURL:   api.assetURL("v0.2.0"),
					SHA256URL:   api.shaURL("v0.2.0"),
				})
			},
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err != nil {
					t.Fatalf("EnsureConfig() error = %v", err)
				}
				assertFileContents(t, path, "cached-kernel")
				if api.hits["latest"] != 1 {
					t.Fatalf("latest release lookups = %d, want 1", api.hits["latest"])
				}
				if api.hits["asset:v0.2.0"] != 0 {
					t.Fatalf("kernel asset downloads = %d, want 0", api.hits["asset:v0.2.0"])
				}
				if api.hits["sha:v0.2.0"] != 0 {
					t.Fatalf("checksum downloads = %d, want 0", api.hits["sha:v0.2.0"])
				}
			},
		},
		{
			name:   "release://latest refreshes when resolved tag changes",
			source: "release://latest",
			setup: func(t *testing.T, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				writeCachedKernel(t, filepath.Join(cacheDir, "release-latest", arch), "old-kernel", KernelCacheMetadata{
					SourceKind:  "release-latest",
					ResolvedTag: "v0.1.0",
					KernelURL:   api.assetURL("v0.1.0"),
					SHA256URL:   api.shaURL("v0.1.0"),
				})
				api.latestTag = "v0.2.0"
			},
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err != nil {
					t.Fatalf("EnsureConfig() error = %v", err)
				}
				assertFileContents(t, path, api.kernelBodies["v0.2.0"])
				meta := readKernelMetadata(t, filepath.Join(cacheDir, "release-latest", arch, "metadata.json"))
				if meta.ResolvedTag != "v0.2.0" {
					t.Fatalf("metadata ResolvedTag = %q, want v0.2.0", meta.ResolvedTag)
				}
				if api.hits["asset:v0.2.0"] != 1 {
					t.Fatalf("kernel asset downloads = %d, want 1", api.hits["asset:v0.2.0"])
				}
			},
		},
		{
			name:   "release://latest falls back to cached copy on refresh failure",
			source: "release://latest",
			setup: func(t *testing.T, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				writeCachedKernel(t, filepath.Join(cacheDir, "release-latest", arch), "cached-kernel", KernelCacheMetadata{
					SourceKind:  "release-latest",
					ResolvedTag: "v0.1.0",
					KernelURL:   api.assetURL("v0.1.0"),
					SHA256URL:   api.shaURL("v0.1.0"),
				})
				api.failLatest = true
			},
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err != nil {
					t.Fatalf("EnsureConfig() error = %v", err)
				}
				assertFileContents(t, path, "cached-kernel")
				if api.hits["latest"] != 1 {
					t.Fatalf("latest release lookups = %d, want 1", api.hits["latest"])
				}
				if api.hits["asset:v0.2.0"] != 0 {
					t.Fatalf("kernel asset downloads = %d, want 0", api.hits["asset:v0.2.0"])
				}
			},
		},
		{
			name:   "release://v0.2.0 immutable hit",
			source: "release://v0.2.0",
			setup: func(t *testing.T, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				writeCachedKernel(t, filepath.Join(cacheDir, "release-v0.2.0", arch), "cached-kernel", KernelCacheMetadata{
					SourceKind:  "release-tag",
					ResolvedTag: "v0.2.0",
					KernelURL:   api.assetURL("v0.2.0"),
					SHA256URL:   api.shaURL("v0.2.0"),
				})
			},
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err != nil {
					t.Fatalf("EnsureConfig() error = %v", err)
				}
				wantPath := filepath.Join(cacheDir, "release-v0.2.0", arch, "vmlinux")
				if path != wantPath {
					t.Fatalf("EnsureConfig() path = %q, want %q", path, wantPath)
				}
				assertFileContents(t, path, "cached-kernel")
				if len(api.hits) != 0 {
					t.Fatalf("unexpected remote requests: %#v", api.hits)
				}
			},
		},
		{
			name:   "release checksum mismatch",
			source: "release://latest",
			setup: func(t *testing.T, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				api.shaBodies["v0.2.0"] = strings.Repeat("a", 64) + "  keel-vmlinux-x86_64\n"
			},
			assert: func(t *testing.T, path string, err error, cacheDir string, api *releaseAPIFixture) {
				t.Helper()
				if err == nil {
					t.Fatalf("EnsureConfig() error = nil, want checksum mismatch")
				}
				if !errors.Is(err, errKernelChecksumMismatch) {
					t.Fatalf("EnsureConfig() error = %v, want checksum mismatch", err)
				}
				if path != "" {
					t.Fatalf("EnsureConfig() path = %q, want empty on checksum mismatch", path)
				}
				if _, statErr := os.Stat(filepath.Join(cacheDir, "release-latest", arch, "vmlinux")); !os.IsNotExist(statErr) {
					t.Fatalf("cached kernel unexpectedly promoted, stat error = %v", statErr)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newReleaseAPIFixture(t)
			defer api.Close()

			cacheDir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, cacheDir, api)
			}

			manager := KernelManager{
				HTTPClient:        api.Client(),
				CacheDir:          cacheDir,
				ReleaseAPIBaseURL: api.releasesURL(),
				Arch:              arch,
			}

			path, err := manager.EnsureConfig(context.Background(), config.KernelConfig{Source: tc.source})
			tc.assert(t, path, err, cacheDir, api)
		})
	}
}

func TestURLCacheLayoutIsStable(t *testing.T) {
	cacheDir := t.TempDir()

	cases := []struct {
		name string
		url  string
	}{
		{name: "plain URL", url: "https://example.invalid/kernels/vmlinux"},
		{name: "URL with query", url: "https://example.invalid/kernels/vmlinux?arch=x86_64"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := cacheLayoutForURL(cacheDir, tc.url, "x86_64")
			second := cacheLayoutForURL(cacheDir, tc.url, "x86_64")
			if first.rootDir != second.rootDir {
				t.Fatalf("cache root mismatch: %q != %q", first.rootDir, second.rootDir)
			}
			if !strings.Contains(filepath.Base(first.rootDir), "url-") {
				t.Fatalf("cache root = %q, want url-* prefix", first.rootDir)
			}
		})
	}

	if got, other := cacheLayoutForURL(cacheDir, cases[0].url, "x86_64").rootDir, cacheLayoutForURL(cacheDir, cases[1].url, "x86_64").rootDir; got == other {
		t.Fatalf("different URLs resolved to same cache root: %q", got)
	}
}

func TestKernelManagerEnsureURLSourceRevalidatesWithETag(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("kernel-v1"))
	}))
	defer server.Close()

	manager := KernelManager{
		HTTPClient: server.Client(),
		CacheDir:   t.TempDir(),
		Arch:       "x86_64",
	}

	path, err := manager.EnsureSource(context.Background(), server.URL+"/vmlinux")
	if err != nil {
		t.Fatalf("EnsureSource() first call error = %v", err)
	}
	assertFileContents(t, path, "kernel-v1")

	path, err = manager.EnsureSource(context.Background(), server.URL+"/vmlinux")
	if err != nil {
		t.Fatalf("EnsureSource() second call error = %v", err)
	}
	assertFileContents(t, path, "kernel-v1")
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	layout := cacheLayoutForURL(manager.CacheDir, server.URL+"/vmlinux", "x86_64")
	meta := readKernelMetadata(t, layout.metadataPath)
	if meta.ETag != `"v1"` {
		t.Fatalf("metadata ETag = %q, want %q", meta.ETag, `"v1"`)
	}
}

type releaseAPIFixture struct {
	server       *httptest.Server
	hits         map[string]int
	latestTag    string
	failLatest   bool
	kernelBodies map[string]string
	shaBodies    map[string]string
}

func newReleaseAPIFixture(t *testing.T) *releaseAPIFixture {
	t.Helper()

	fixture := &releaseAPIFixture{
		hits:      make(map[string]int),
		latestTag: "v0.2.0",
		kernelBodies: map[string]string{
			"v0.1.0": "kernel-v0.1.0",
			"v0.2.0": "kernel-v0.2.0",
		},
		shaBodies: make(map[string]string),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/moolen/keel/releases/latest":
			fixture.hits["latest"]++
			if fixture.failLatest {
				http.Error(w, "boom", http.StatusBadGateway)
				return
			}
			fixture.writeReleaseJSON(t, w, fixture.latestTag)
		case strings.HasPrefix(r.URL.Path, "/repos/moolen/keel/releases/tags/"):
			tag := strings.TrimPrefix(r.URL.Path, "/repos/moolen/keel/releases/tags/")
			fixture.hits["tag:"+tag]++
			fixture.writeReleaseJSON(t, w, tag)
		case strings.HasPrefix(r.URL.Path, "/assets/") && strings.HasSuffix(r.URL.Path, ".sha256"):
			tag := pathTag(r.URL.Path)
			fixture.hits["sha:"+tag]++
			body := fixture.shaBodies[tag]
			if body == "" {
				body = checksumLine(fixture.kernelBodies[tag], "keel-vmlinux-x86_64")
			}
			_, _ = w.Write([]byte(body))
		case strings.HasPrefix(r.URL.Path, "/assets/"):
			tag := pathTag(r.URL.Path)
			fixture.hits["asset:"+tag]++
			w.Header().Set("ETag", `"`+tag+`"`)
			_, _ = w.Write([]byte(fixture.kernelBodies[tag]))
		default:
			http.NotFound(w, r)
		}
	})

	fixture.server = httptest.NewServer(handler)
	return fixture
}

func (f *releaseAPIFixture) Close() {
	f.server.Close()
}

func (f *releaseAPIFixture) Client() *http.Client {
	return f.server.Client()
}

func (f *releaseAPIFixture) releasesURL() string {
	return f.server.URL + "/repos/moolen/keel/releases"
}

func (f *releaseAPIFixture) assetURL(tag string) string {
	return f.server.URL + "/assets/" + tag + "/keel-vmlinux-x86_64"
}

func (f *releaseAPIFixture) shaURL(tag string) string {
	return f.assetURL(tag) + ".sha256"
}

func (f *releaseAPIFixture) writeReleaseJSON(t *testing.T, w http.ResponseWriter, tag string) {
	t.Helper()

	payload := map[string]any{
		"tag_name": tag,
		"assets": []map[string]string{
			{
				"name":                 "keel-vmlinux-x86_64",
				"browser_download_url": f.assetURL(tag),
			},
			{
				"name":                 "keel-vmlinux-x86_64.sha256",
				"browser_download_url": f.shaURL(tag),
			},
		},
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}

func writeCachedKernel(t *testing.T, dir, contents string, metadata KernelCacheMetadata) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmlinux"), []byte(contents), 0o755); err != nil {
		t.Fatalf("WriteFile(vmlinux) error = %v", err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644); err != nil {
		t.Fatalf("WriteFile(metadata.json) error = %v", err)
	}
}

func readKernelMetadata(t *testing.T, path string) KernelCacheMetadata {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	var metadata KernelCacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("Unmarshal(%q) error = %v", path, err)
	}
	return metadata
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("file contents = %q, want %q", string(data), want)
	}
}

func checksumLine(body, name string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func pathTag(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
