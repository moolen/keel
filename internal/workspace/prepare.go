package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	if err := os.MkdirAll(filepath.Dir(opts.ImagePath), 0o755); err != nil {
		return PrepareResult{}, err
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dM", opts.SizeMB), opts.ImagePath).Run(); err != nil {
		return PrepareResult{}, fmt.Errorf("create sparse image: %w", err)
	}

	cmd := exec.Command("mkfs.ext4", "-q", "-F", "-L", opts.Label, "-d", opts.SourceDir, opts.ImagePath)
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
