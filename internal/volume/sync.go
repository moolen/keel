package volume

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/moolen/keel/internal/workspace"
)

type SyncOptions struct {
	SourcePath string
	ImagePath  string
	Kind       string
	Subpath    string
}

func SyncImage(opts SyncOptions) error {
	switch opts.Kind {
	case "dir":
		_, err := workspace.SyncImage(workspace.ImageSyncOptions{
			HostDir:   opts.SourcePath,
			ImagePath: opts.ImagePath,
		})
		return err
	case "file":
		mountDir, cleanup, err := mountImageReadOnly(opts.ImagePath)
		if err != nil {
			return err
		}
		defer cleanup()
		sourceFile := filepath.Join(mountDir, opts.Subpath)
		info, err := os.Stat(sourceFile)
		if err != nil {
			if os.IsNotExist(err) {
				return os.Remove(opts.SourcePath)
			}
			return err
		}
		return copyPath(sourceFile, opts.SourcePath, info.Mode().Perm())
	default:
		return fmt.Errorf("unknown volume kind %q", opts.Kind)
	}
}

func mountImageReadOnly(imagePath string) (string, func(), error) {
	mountDir, err := os.MkdirTemp("", "keel-volume-mount-*")
	if err != nil {
		return "", nil, err
	}
	cmd := exec.CommandContext(context.Background(), "sudo", "mount", "-o", "loop,ro", imagePath, mountDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(mountDir)
		return "", nil, fmt.Errorf("mount volume image: %w: %s", err, output)
	}
	cleanup := func() {
		_ = exec.CommandContext(context.Background(), "sudo", "umount", mountDir).Run()
		_ = os.RemoveAll(mountDir)
	}
	return mountDir, cleanup, nil
}
