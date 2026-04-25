package image

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type Puller struct {
	Fetch func(context.Context, string) (v1.Image, error)
}

type PullResult struct {
	Layout CacheLayout
}

type CachedImage struct {
	Reference  string
	RootfsPath string
}

func (p Puller) PullAndCache(ctx context.Context, cacheDir, ref string) (PullResult, error) {
	layout, err := ResolveCacheLayout(cacheDir, ref)
	if err != nil {
		return PullResult{}, err
	}
	if err := os.MkdirAll(layout.Directory, 0o755); err != nil {
		return PullResult{}, err
	}

	fetch := p.Fetch
	if fetch == nil {
		fetch = fetchRemoteImage
	}
	img, err := fetch(ctx, ref)
	if err != nil {
		return PullResult{}, err
	}

	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return PullResult{}, err
	}
	if err := tarball.WriteToFile(layout.OCIPath, parsedRef, img); err != nil {
		return PullResult{}, fmt.Errorf("write image tarball: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "keel-rootfs-*")
	if err != nil {
		return PullResult{}, err
	}
	defer os.RemoveAll(tempDir)

	if err := extractFilesystem(mutate.Extract(img), tempDir); err != nil {
		return PullResult{}, err
	}
	if _, err := CreateRootfsImage(CreateRootfsOptions{
		SourceDir: tempDir,
		ImagePath: layout.RootfsPath,
		SizeMB:    2048,
	}); err != nil {
		return PullResult{}, err
	}

	return PullResult{Layout: layout}, nil
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
		return nil, fmt.Errorf("fetch remote image: %w", err)
	}
	return img, nil
}

func extractFilesystem(reader io.ReadCloser, dst string) error {
	defer reader.Close()

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
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
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
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
}
