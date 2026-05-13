package volume

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/moolen/keel/internal/ext4"
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
		mountDir, cleanup, err := ext4.MountReadOnly(opts.ImagePath, "keel-volume-mount-*", false)
		if err != nil {
			return fmt.Errorf("mount volume image: %w", err)
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
