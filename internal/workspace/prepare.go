package workspace

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/moolen/keel/internal/paths"
)

type PrepareOptions struct {
	SourceDir  string
	ImagePath  string
	SizeMB     int
	Label      string
	Mountpoint string
}

type PrepareResult struct {
	ImagePath string
	SizeBytes int64
}

func PrepareImage(opts PrepareOptions) (PrepareResult, error) {
	if opts.SourceDir == "" {
		return PrepareResult{}, fmt.Errorf("source directory is required")
	}
	if opts.ImagePath == "" {
		return PrepareResult{}, fmt.Errorf("image path is required")
	}
	if opts.SizeMB <= 0 {
		opts.SizeMB = 1024
	}
	if opts.Label == "" {
		opts.Label = "workspace"
	}

	stagedDir, err := snapshotDirectory(opts.SourceDir)
	if err != nil {
		return PrepareResult{}, err
	}
	defer func() {
		_ = os.RemoveAll(stagedDir)
	}()

	if err := os.MkdirAll(filepath.Dir(opts.ImagePath), 0o755); err != nil {
		return PrepareResult{}, err
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dM", opts.SizeMB), opts.ImagePath).Run(); err != nil {
		return PrepareResult{}, fmt.Errorf("create sparse image: %w", err)
	}

	cmd := exec.Command("mkfs.ext4", "-q", "-F", "-L", opts.Label, "-d", stagedDir, opts.ImagePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return PrepareResult{}, fmt.Errorf("mkfs.ext4: %w: %s", err, output)
	}

	info, err := os.Stat(opts.ImagePath)
	if err != nil {
		return PrepareResult{}, err
	}
	return PrepareResult{
		ImagePath: opts.ImagePath,
		SizeBytes: info.Size(),
	}, nil
}

func snapshotDirectory(source string) (string, error) {
	stageDir, err := paths.NewTempDir("keel-workspace-stage-*")
	if err != nil {
		return "", err
	}

	err = filepath.WalkDir(source, func(path string, d os.DirEntry, walkErr error) error {
		if os.IsNotExist(walkErr) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(stageDir, rel)

		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}

		switch mode := info.Mode(); {
		case mode.IsDir():
			return os.MkdirAll(target, mode.Perm())
		case mode&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.Symlink(linkTarget, target)
		case mode.IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return copyFile(path, target, mode.Perm())
		default:
			return nil
		}
	})
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	return stageDir, nil
}

func copyFile(source, target string, perm os.FileMode) error {
	src, err := os.Open(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()

	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		_ = dst.Close()
	}()

	if _, err := io.Copy(dst, src); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return nil
}
