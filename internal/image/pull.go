package image

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type Puller struct {
	Fetch         func(context.Context, string) (v1.Image, error)
	ResolveDigest func(context.Context, string) (string, error)
	GuestInit     func() (GuestAgentAssets, error)
	GuestTrust    GuestTrustAssets
	Progress      func(PullProgress)
}

type PullResult struct {
	Layout CacheLayout
}

type CachedImage struct {
	Reference  string
	RootfsPath string
	SizeBytes  int64
}

type PullPhase string

const (
	PullPhaseResolve     PullPhase = "resolving image metadata"
	PullPhaseDownload    PullPhase = "downloading image layers"
	PullPhaseExtract     PullPhase = "extracting filesystem"
	PullPhaseBuildRootfs PullPhase = "building rootfs image"
	PullPhaseReady       PullPhase = "image ready"
)

func (p PullPhase) String() string {
	return string(p)
}

type PullProgress struct {
	Phase   PullPhase
	Current int64
	Total   int64
}

func (p Puller) PullAndCache(ctx context.Context, cacheDir, ref string) (PullResult, error) {
	layout, err := ResolveCacheLayout(cacheDir, ref)
	if err != nil {
		return PullResult{}, err
	}
	if cacheLayoutReady(layout, p.GuestInit != nil) {
		refresh, err := p.shouldRefreshCache(ctx, layout, ref)
		if err != nil {
			return PullResult{}, err
		}
		if !refresh {
			return PullResult{Layout: layout}, nil
		}
		if err := os.RemoveAll(layout.Directory); err != nil {
			return PullResult{}, err
		}
	}
	if err := os.MkdirAll(layout.Directory, 0o755); err != nil {
		return PullResult{}, err
	}

	fetch := p.Fetch
	if fetch == nil {
		fetch = fetchRemoteImage
	}
	p.reportProgress(PullProgress{Phase: PullPhaseResolve})
	img, err := fetch(ctx, ref)
	if err != nil {
		return PullResult{}, err
	}

	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return PullResult{}, err
	}
	progressUpdates := make(chan v1.Update, 32)
	var progressWG sync.WaitGroup
	if p.Progress != nil {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			for update := range progressUpdates {
				if update.Total <= 0 && update.Complete <= 0 {
					continue
				}
				p.reportProgress(PullProgress{
					Phase:   PullPhaseDownload,
					Current: update.Complete,
					Total:   update.Total,
				})
			}
		}()
	}
	err = tarball.WriteToFile(layout.OCIPath, parsedRef, img, tarball.WithProgress(progressUpdates))
	close(progressUpdates)
	progressWG.Wait()
	if err != nil {
		return PullResult{}, fmt.Errorf("write image tarball: %w", err)
	}
	if err := writeImageDigest(layout.DigestPath, img); err != nil {
		return PullResult{}, err
	}

	tempDir, err := os.MkdirTemp("", "keel-rootfs-*")
	if err != nil {
		return PullResult{}, err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	p.reportProgress(PullProgress{Phase: PullPhaseExtract})
	if err := extractFilesystem(mutate.Extract(img), tempDir); err != nil {
		return PullResult{}, err
	}
	p.reportProgress(PullProgress{Phase: PullPhaseBuildRootfs})
	if _, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: tempDir,
		ImagePath: layout.RootfsPath,
		SizeMB:    2048,
	}); err != nil {
		return PullResult{}, err
	}
	if p.GuestInit != nil {
		assets, err := p.GuestInit()
		if err != nil {
			return PullResult{}, err
		}
		if _, err := EnsureGuestAgent(layout.RootfsPath, layout.AgentPath, assets); err != nil {
			return PullResult{}, err
		}
	}
	if err := InjectGuestTrust(layout.RootfsPath, p.GuestTrust); err != nil {
		return PullResult{}, err
	}
	p.reportProgress(PullProgress{Phase: PullPhaseReady, Current: 1, Total: 1})

	return PullResult{Layout: layout}, nil
}

func (p Puller) shouldRefreshCache(ctx context.Context, layout CacheLayout, ref string) (bool, error) {
	if referenceUsesDigest(ref) {
		return false, nil
	}
	data, err := os.ReadFile(layout.DigestPath)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return true, nil
	default:
		return false, err
	}

	resolveDigest := p.ResolveDigest
	if resolveDigest == nil {
		resolveDigest = resolveRemoteDigest
	}
	remoteDigest, err := resolveDigest(ctx, ref)
	if err != nil {
		// Fail open when a mutable tag cannot be revalidated.
		return false, nil
	}
	return strings.TrimSpace(string(data)) != strings.TrimSpace(remoteDigest), nil
}

func (p Puller) reportProgress(update PullProgress) {
	if p.Progress != nil {
		p.Progress(update)
	}
}

func cacheLayoutReady(layout CacheLayout, requireAgent bool) bool {
	required := []string{layout.RootfsPath, layout.OCIPath}
	if requireAgent {
		required = append(required, layout.AgentPath)
	}
	for _, path := range required {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

func ListCachedImages(cacheDir string) ([]CachedImage, error) {
	var images []CachedImage
	err := filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "rootfs.ext4" {
			return nil
		}
		rel, err := filepath.Rel(cacheDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 {
			return nil
		}
		registry := parts[0]
		tag := parts[len(parts)-1]
		repository := strings.Join(parts[1:len(parts)-1], "/")
		images = append(images, CachedImage{
			Reference:  fmt.Sprintf("%s/%s:%s", registry, repository, tag),
			RootfsPath: path,
			SizeBytes:  sizeForFile(path),
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i].Reference < images[j].Reference
	})
	return images, nil
}

func sizeForFile(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func RemoveCachedImage(cacheDir, ref string) error {
	layout, err := ResolveCacheLayout(cacheDir, ref)
	if err != nil {
		return err
	}
	return os.RemoveAll(layout.Directory)
}

func fetchRemoteImage(ctx context.Context, ref string) (v1.Image, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	img, err := remote.Image(parsedRef, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("fetch remote image %q: %s", ref, describeRemoteImageError(err))
	}
	return img, nil
}

func resolveRemoteDigest(ctx context.Context, ref string) (string, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse image reference: %w", err)
	}
	desc, err := remote.Head(parsedRef, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("resolve image digest %q: %s", ref, describeRemoteImageError(err))
	}
	return desc.Digest.String(), nil
}

func writeImageDigest(path string, img v1.Image) error {
	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("compute image digest: %w", err)
	}
	if err := os.WriteFile(path, []byte(digest.String()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write image digest: %w", err)
	}
	return nil
}

func describeRemoteImageError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	text := err.Error()
	lower := strings.ToLower(text)
	if strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "denied") ||
		strings.Contains(lower, "401") {
		return text + "; check that the image exists and run `docker login` for the registry if it is private"
	}
	if strings.Contains(lower, "no such host") || strings.Contains(lower, "dial tcp") || strings.Contains(lower, "tls handshake timeout") {
		return text + "; check host network connectivity and registry DNS/TLS access"
	}
	return text
}

func extractFilesystem(reader io.ReadCloser, dst string) error {
	defer func() {
		_ = reader.Close()
	}()

	tr := tar.NewReader(reader)
	dirModes := make(map[string]os.FileMode)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read layer tar: %w", err)
		}

		target := filepath.Join(dst, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dst)+string(os.PathSeparator)) && filepath.Clean(target) != filepath.Clean(dst) {
			return fmt.Errorf("invalid archive path %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Create directories writable during extraction, then restore the image mode.
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			dirModes[target] = os.FileMode(hdr.Mode)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				_ = file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			if err := os.Chmod(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}

	// Apply final directory modes after all nested entries are materialized.
	paths := make([]string, 0, len(dirModes))
	for path := range dirModes {
		paths = append(paths, path)
	}
	slices.SortFunc(paths, func(a, b string) int {
		if len(a) == len(b) {
			return strings.Compare(a, b)
		}
		return len(b) - len(a)
	})
	for _, path := range paths {
		if err := os.Chmod(path, dirModes[path]); err != nil {
			return err
		}
	}
	return nil
}
