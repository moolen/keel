package volume

import (
	"io"
	"os"
	"path/filepath"

	"github.com/moolen/keel/internal/workspace"
)

const filePayloadName = "payload"

type PrepareOptions struct {
	SourcePath string
	ImagePath  string
	SizeMB     int
	Label      string
}

type PrepareResult struct {
	ImagePath string
	Kind      string
	Subpath   string
}

func PrepareImage(opts PrepareOptions) (PrepareResult, error) {
	info, err := os.Stat(opts.SourcePath)
	if err != nil {
		return PrepareResult{}, err
	}
	switch {
	case info.IsDir():
		if _, err := workspace.PrepareImage(workspace.PrepareOptions{
			SourceDir: opts.SourcePath,
			ImagePath: opts.ImagePath,
			SizeMB:    opts.SizeMB,
			Label:     opts.Label,
		}); err != nil {
			return PrepareResult{}, err
		}
		return PrepareResult{ImagePath: opts.ImagePath, Kind: "dir"}, nil
	default:
		stageDir, err := os.MkdirTemp("", "keel-volume-file-*")
		if err != nil {
			return PrepareResult{}, err
		}
		defer func() { _ = os.RemoveAll(stageDir) }()
		if err := copyPath(opts.SourcePath, filepath.Join(stageDir, filePayloadName), info.Mode().Perm()); err != nil {
			return PrepareResult{}, err
		}
		if _, err := workspace.PrepareImage(workspace.PrepareOptions{
			SourceDir: stageDir,
			ImagePath: opts.ImagePath,
			SizeMB:    opts.SizeMB,
			Label:     opts.Label,
		}); err != nil {
			return PrepareResult{}, err
		}
		return PrepareResult{ImagePath: opts.ImagePath, Kind: "file", Subpath: filePayloadName}, nil
	}
}

func copyPath(source, target string, perm os.FileMode) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return nil
}
