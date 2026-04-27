package image

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const mib = int64(1024 * 1024)

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
	estimatedSizeMB, err := estimateRootfsSizeMB(opts.SourceDir)
	if err != nil {
		return CreateRootfsResult{}, err
	}
	if opts.SizeMB <= 0 || estimatedSizeMB > opts.SizeMB {
		opts.SizeMB = estimatedSizeMB
	}
	if opts.Label == "" {
		opts.Label = "rootfs"
	}

	if err := os.MkdirAll(filepath.Dir(opts.ImagePath), 0o755); err != nil {
		return CreateRootfsResult{}, err
	}
	if err := exec.CommandContext(context.Background(), "truncate", "-s", fmt.Sprintf("%dM", opts.SizeMB), opts.ImagePath).Run(); err != nil {
		return CreateRootfsResult{}, fmt.Errorf("create sparse image: %w", err)
	}
	cmd := exec.CommandContext(context.Background(), "mkfs.ext4", "-q", "-F", "-L", opts.Label, "-d", opts.SourceDir, opts.ImagePath)
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

func estimateRootfsSizeMB(sourceDir string) (int, error) {
	var totalBytes int64
	var entryCount int64

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		entryCount++
		if info.Mode().IsRegular() {
			totalBytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("walk rootfs source: %w", err)
	}

	// Reserve slack for ext4 metadata, block/inode overhead, and image growth.
	overheadBytes := totalBytes/4 + 512*mib + entryCount*4096
	sizeBytes := totalBytes + overheadBytes
	sizeMB := int((sizeBytes + mib - 1) / mib)
	if sizeMB < 2048 {
		sizeMB = 2048
	}
	return sizeMB, nil
}
