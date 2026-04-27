package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/moolen/keel/internal/config"
)

const (
	kernelReleaseRepoOwner = "moolen"
	kernelReleaseRepoName  = "keel"
)

var errKernelChecksumMismatch = errors.New("kernel checksum mismatch")

type ReleaseKernelAsset struct {
	Tag       string
	KernelURL string
	SHA256URL string
	AssetName string
}

type githubRelease struct {
	TagName string               `json:"tag_name"`
	Assets  []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type kernelDownloadResult struct {
	statusCode   int
	etag         string
	lastModified string
}

func (m KernelManager) EnsureConfig(ctx context.Context, cfg config.KernelConfig) (string, error) {
	if cfg.Path != "" {
		if err := validateKernelPath(cfg.Path); err != nil {
			return "", err
		}
		return cfg.Path, nil
	}

	source := cfg.Source
	if source == "" {
		source = "release://latest"
	}
	return m.EnsureSource(ctx, source)
}

func (m KernelManager) EnsureSource(ctx context.Context, source string) (string, error) {
	switch {
	case strings.HasPrefix(source, "release://"):
		return m.ensureReleaseSource(ctx, source)
	case strings.HasPrefix(source, "http://"), strings.HasPrefix(source, "https://"):
		return m.ensureURLSource(ctx, source)
	default:
		return "", fmt.Errorf("unsupported kernel source %q", source)
	}
}

func validateKernelPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open kernel path %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat kernel path %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("kernel path %q is a directory", path)
	}
	return nil
}

func (m KernelManager) ensureReleaseSource(ctx context.Context, source string) (string, error) {
	arch := m.resolveArch()
	cacheDir := m.kernelCacheDir()

	if source == "release://latest" {
		layout := cacheLayoutForReleaseLatest(cacheDir, arch)
		return m.ensureLatestRelease(ctx, layout, arch)
	}

	tag, err := parseReleaseTag(source)
	if err != nil {
		return "", err
	}
	layout := cacheLayoutForReleaseTag(cacheDir, tag, arch)
	if layout.hasKernel() {
		return layout.kernelPath, nil
	}

	asset, err := m.resolveReleaseAsset(ctx, source, arch)
	if err != nil {
		return "", err
	}
	return m.downloadReleaseIntoCache(ctx, layout, asset, "release-tag", nil)
}

func (m KernelManager) ensureLatestRelease(ctx context.Context, layout kernelCacheLayout, arch string) (string, error) {
	hasCachedKernel := layout.hasKernel()
	metadata, metadataErr := loadKernelCacheMetadata(layout.metadataPath)

	asset, err := m.resolveReleaseAsset(ctx, "release://latest", arch)
	if err != nil {
		if hasCachedKernel {
			return layout.kernelPath, nil
		}
		return "", err
	}

	if hasCachedKernel && metadataErr == nil && metadata.ResolvedTag == asset.Tag {
		switch {
		case metadata.SHA256URL != "":
			expectedChecksum, checksumErr := m.downloadExpectedChecksum(ctx, asset.SHA256URL)
			if checksumErr == nil {
				if verifyErr := verifyFileChecksum(layout.kernelPath, expectedChecksum); verifyErr == nil {
					if metadata.SHA256 != expectedChecksum || metadata.KernelURL != asset.KernelURL || metadata.SHA256URL != asset.SHA256URL {
						metadata.SHA256 = expectedChecksum
						metadata.KernelURL = asset.KernelURL
						metadata.SHA256URL = asset.SHA256URL
						if writeErr := writeKernelCacheMetadata(layout.metadataPath, metadata); writeErr == nil {
							return layout.kernelPath, nil
						}
					} else {
						return layout.kernelPath, nil
					}
				}
			}
		case metadata.ETag != "" || metadata.LastModified != "":
			headers := make(http.Header)
			if metadata.ETag != "" {
				headers.Set("If-None-Match", metadata.ETag)
			}
			if metadata.LastModified != "" {
				headers.Set("If-Modified-Since", metadata.LastModified)
			}
			path, downloadErr := m.downloadReleaseIntoCache(ctx, layout, asset, "release-latest", headers)
			if downloadErr == nil {
				return path, nil
			}
			if !errors.Is(downloadErr, errKernelChecksumMismatch) {
				return layout.kernelPath, nil
			}
			return "", downloadErr
		default:
			return layout.kernelPath, nil
		}
	}

	path, err := m.downloadReleaseIntoCache(ctx, layout, asset, "release-latest", nil)
	if err != nil {
		if hasCachedKernel && !errors.Is(err, errKernelChecksumMismatch) {
			return layout.kernelPath, nil
		}
		return "", err
	}
	return path, nil
}

func (m KernelManager) ensureURLSource(ctx context.Context, source string) (string, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid kernel URL %q", source)
	}

	layout := cacheLayoutForURL(m.kernelCacheDir(), source, m.resolveArch())
	if !layout.hasKernel() {
		return m.downloadURLIntoCache(ctx, layout, source, KernelCacheMetadata{
			SourceKind: "url",
			KernelURL:  source,
		}, nil)
	}

	metadata, err := loadKernelCacheMetadata(layout.metadataPath)
	if err != nil {
		return m.downloadURLIntoCache(ctx, layout, source, KernelCacheMetadata{
			SourceKind: "url",
			KernelURL:  source,
		}, nil)
	}
	if metadata.ETag == "" && metadata.LastModified == "" {
		return layout.kernelPath, nil
	}

	headers := make(http.Header)
	if metadata.ETag != "" {
		headers.Set("If-None-Match", metadata.ETag)
	}
	if metadata.LastModified != "" {
		headers.Set("If-Modified-Since", metadata.LastModified)
	}

	return m.downloadURLIntoCache(ctx, layout, source, KernelCacheMetadata{
		SourceKind: "url",
		KernelURL:  source,
	}, headers)
}

func (m KernelManager) downloadReleaseIntoCache(ctx context.Context, layout kernelCacheLayout, asset ReleaseKernelAsset, sourceKind string, headers http.Header) (string, error) {
	metadata := KernelCacheMetadata{
		SourceKind:  sourceKind,
		ResolvedTag: asset.Tag,
		KernelURL:   asset.KernelURL,
		SHA256URL:   asset.SHA256URL,
	}
	return m.downloadURLIntoCache(ctx, layout, asset.KernelURL, metadata, headers)
}

func (m KernelManager) downloadURLIntoCache(ctx context.Context, layout kernelCacheLayout, sourceURL string, metadata KernelCacheMetadata, headers http.Header) (string, error) {
	if err := os.MkdirAll(layout.archDir, 0o755); err != nil {
		return "", err
	}

	tempFile, err := os.CreateTemp(layout.archDir, "vmlinux-*.tmp")
	if err != nil {
		return "", err
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	defer func() {
		_ = os.Remove(tempPath)
	}()

	result, err := m.downloadKernelToPath(ctx, sourceURL, tempPath, headers)
	if err != nil {
		return "", err
	}
	if result.statusCode == http.StatusNotModified {
		return layout.kernelPath, nil
	}

	expectedChecksum := ""
	if metadata.SHA256URL != "" {
		expectedChecksum, err = m.downloadExpectedChecksum(ctx, metadata.SHA256URL)
		if err != nil {
			return "", err
		}
		if err := verifyFileChecksum(tempPath, expectedChecksum); err != nil {
			return "", err
		}
	}

	metadata.KernelURL = sourceURL
	metadata.SHA256 = expectedChecksum
	metadata.ETag = result.etag
	metadata.LastModified = result.lastModified

	if err := writeKernelCacheMetadata(layout.metadataPath, metadata); err != nil {
		return "", err
	}
	if err := os.Rename(tempPath, layout.kernelPath); err != nil {
		return "", err
	}
	return layout.kernelPath, nil
}

func (m KernelManager) downloadKernelToPath(ctx context.Context, sourceURL, destPath string, headers http.Header) (kernelDownloadResult, error) {
	resp, err := m.doRequest(ctx, http.MethodGet, sourceURL, headers)
	if err != nil {
		return kernelDownloadResult{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return kernelDownloadResult{
			statusCode:   resp.StatusCode,
			etag:         resp.Header.Get("ETag"),
			lastModified: resp.Header.Get("Last-Modified"),
		}, nil
	default:
		return kernelDownloadResult{}, fmt.Errorf("download kernel: unexpected status %s", resp.Status)
	}

	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return kernelDownloadResult{}, err
	}
	defer func() {
		_ = file.Close()
	}()

	m.reportProgress(KernelProgress{
		Phase:   "downloading kernel",
		Current: 0,
		Total:   max(resp.ContentLength, 0),
	})
	if _, err := copyWithProgress(file, resp.Body, func(written int64) {
		m.reportProgress(KernelProgress{
			Phase:   "downloading kernel",
			Current: written,
			Total:   max(resp.ContentLength, 0),
		})
	}); err != nil {
		return kernelDownloadResult{}, err
	}

	return kernelDownloadResult{
		statusCode:   resp.StatusCode,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

func (m KernelManager) downloadExpectedChecksum(ctx context.Context, checksumURL string) (string, error) {
	resp, err := m.doRequest(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksum: unexpected status %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseChecksum(string(data))
}

func verifyFileChecksum(path, want string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		return fmt.Errorf("%w: got %s want %s", errKernelChecksumMismatch, got, want)
	}
	return nil
}

func parseChecksum(body string) (string, error) {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return "", fmt.Errorf("checksum file is empty")
	}
	sum := strings.ToLower(fields[0])
	if len(sum) != 64 {
		return "", fmt.Errorf("invalid checksum %q", sum)
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", fmt.Errorf("invalid checksum %q: %w", sum, err)
	}
	return sum, nil
}

func (m KernelManager) resolveReleaseAsset(ctx context.Context, source, arch string) (ReleaseKernelAsset, error) {
	releaseURL, err := m.releaseLookupURL(source)
	if err != nil {
		return ReleaseKernelAsset{}, err
	}

	headers := make(http.Header)
	headers.Set("Accept", "application/vnd.github+json")
	headers.Set("User-Agent", "keel")
	resp, err := m.doRequest(ctx, http.MethodGet, releaseURL, headers)
	if err != nil {
		return ReleaseKernelAsset{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return ReleaseKernelAsset{}, fmt.Errorf("release %q not found", strings.TrimPrefix(source, "release://"))
	default:
		return ReleaseKernelAsset{}, fmt.Errorf("resolve release asset: unexpected status %s", resp.Status)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ReleaseKernelAsset{}, err
	}

	assetName := releaseKernelAssetName(arch)
	checksumName := assetName + ".sha256"

	var kernelURL, checksumURL string
	for _, asset := range release.Assets {
		switch asset.Name {
		case assetName:
			kernelURL = asset.BrowserDownloadURL
		case checksumName:
			checksumURL = asset.BrowserDownloadURL
		}
	}

	if kernelURL == "" {
		return ReleaseKernelAsset{}, fmt.Errorf("release %s is missing asset %q", release.TagName, assetName)
	}
	return ReleaseKernelAsset{
		Tag:       release.TagName,
		KernelURL: kernelURL,
		SHA256URL: checksumURL,
		AssetName: assetName,
	}, nil
}

func (m KernelManager) releaseLookupURL(source string) (string, error) {
	base := strings.TrimRight(m.releaseAPIBaseURL(), "/")
	if source == "release://latest" {
		return base + "/latest", nil
	}
	tag, err := parseReleaseTag(source)
	if err != nil {
		return "", err
	}
	return base + "/tags/" + url.PathEscape(tag), nil
}

func (m KernelManager) releaseAPIBaseURL() string {
	if m.ReleaseAPIBaseURL != "" {
		return m.ReleaseAPIBaseURL
	}
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", kernelReleaseRepoOwner, kernelReleaseRepoName)
}

func (m KernelManager) doRequest(ctx context.Context, method, targetURL string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	return m.httpClient().Do(req)
}

func parseReleaseTag(source string) (string, error) {
	if !strings.HasPrefix(source, "release://") {
		return "", fmt.Errorf("unsupported release source %q", source)
	}
	tag := strings.TrimPrefix(source, "release://")
	if tag == "" || tag == "latest" {
		return "", fmt.Errorf("unsupported release source %q", source)
	}
	return tag, nil
}

func releaseKernelAssetName(arch string) string {
	return "keel-vmlinux-" + arch
}
