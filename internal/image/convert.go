package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type CreateRootfsOptions struct {
	SourceDir string
	ImagePath string
	SizeMB    int
	Label     string
}

type CreateRootfsResult struct {
	ImagePath string
	SizeBytes int64
}

func CreateRootfsImage(opts CreateRootfsOptions) (CreateRootfsResult, error) {
	if opts.SourceDir == "" {
		return CreateRootfsResult{}, fmt.Errorf("source directory is required")
	}
	if opts.ImagePath == "" {
		return CreateRootfsResult{}, fmt.Errorf("image path is required")
	}
	if opts.SizeMB <= 0 {
		opts.SizeMB = 2048
	}
	if opts.Label == "" {
		opts.Label = "rootfs"
	}

	if err := os.MkdirAll(filepath.Dir(opts.ImagePath), 0o755); err != nil {
		return CreateRootfsResult{}, err
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dM", opts.SizeMB), opts.ImagePath).Run(); err != nil {
		return CreateRootfsResult{}, fmt.Errorf("create sparse image: %w", err)
	}
	cmd := exec.Command("mkfs.ext4", "-q", "-F", "-L", opts.Label, "-d", opts.SourceDir, opts.ImagePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return CreateRootfsResult{}, fmt.Errorf("mkfs.ext4: %w: %s", err, output)
	}

	info, err := os.Stat(opts.ImagePath)
	if err != nil {
		return CreateRootfsResult{}, err
	}
	return CreateRootfsResult{
		ImagePath: opts.ImagePath,
		SizeBytes: info.Size(),
	}, nil
}
