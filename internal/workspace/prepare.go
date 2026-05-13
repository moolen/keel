package workspace

import (
	"github.com/moolen/keel/internal/ext4"
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
	if opts.Label == "" {
		opts.Label = "workspace"
	}
	result, err := ext4.CreateImage(ext4.CreateOptions{
		SourceDir:      opts.SourceDir,
		ImagePath:      opts.ImagePath,
		SizeMB:         opts.SizeMB,
		Label:          opts.Label,
		StageSourceDir: true,
	})
	if err != nil {
		return PrepareResult{}, err
	}
	return PrepareResult{
		ImagePath: result.ImagePath,
		SizeBytes: result.SizeBytes,
	}, nil
}
