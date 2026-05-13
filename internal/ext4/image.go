package ext4

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/moolen/keel/internal/paths"
)

type CreateOptions struct {
	SourceDir      string
	ImagePath      string
	SizeMB         int
	Label          string
	StageSourceDir bool
}

type CreateResult struct {
	ImagePath string
	SizeBytes int64
}

func CreateImage(opts CreateOptions) (CreateResult, error) {
	if opts.SourceDir == "" {
		return CreateResult{}, fmt.Errorf("source directory is required")
	}
	if opts.ImagePath == "" {
		return CreateResult{}, fmt.Errorf("image path is required")
	}
	if opts.SizeMB <= 0 {
		opts.SizeMB = 1024
	}
	if opts.Label == "" {
		opts.Label = "ext4"
	}

	sourceDir := opts.SourceDir
	if opts.StageSourceDir {
		stagedDir, err := snapshotDirectory(opts.SourceDir)
		if err != nil {
			return CreateResult{}, err
		}
		defer func() {
			_ = os.RemoveAll(stagedDir)
		}()
		sourceDir = stagedDir
	}

	if err := os.MkdirAll(filepath.Dir(opts.ImagePath), 0o755); err != nil {
		return CreateResult{}, err
	}
	if err := exec.CommandContext(context.Background(), "truncate", "-s", fmt.Sprintf("%dM", opts.SizeMB), opts.ImagePath).Run(); err != nil {
		return CreateResult{}, fmt.Errorf("create sparse image: %w", err)
	}

	cmd := exec.CommandContext(context.Background(), "mkfs.ext4", "-q", "-F", "-L", opts.Label, "-d", sourceDir, opts.ImagePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return CreateResult{}, fmt.Errorf("mkfs.ext4: %w: %s", err, output)
	}

	info, err := os.Stat(opts.ImagePath)
	if err != nil {
		return CreateResult{}, err
	}
	return CreateResult{
		ImagePath: opts.ImagePath,
		SizeBytes: info.Size(),
	}, nil
}

func CopySparseFile(sourcePath, targetPath string) error {
	src, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open source image: %w", err)
	}
	defer func() {
		_ = src.Close()
	}()
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat source image: %w", err)
	}
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove target image: %w", err)
	}
	dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create target image: %w", err)
	}
	defer func() {
		_ = dst.Close()
	}()
	if err := copySparseFile(dst, src, info.Size()); err != nil {
		return fmt.Errorf("copy sparse image: %w", err)
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("sync target image: %w", err)
	}
	return nil
}

func GrowImage(imagePath string, minSizeMB int) error {
	if minSizeMB <= 0 {
		return nil
	}
	info, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("stat image: %w", err)
	}
	targetBytes := int64(minSizeMB) * 1024 * 1024
	if info.Size() >= targetBytes {
		return nil
	}
	if err := exec.CommandContext(context.Background(), "truncate", "-s", fmt.Sprintf("%dM", minSizeMB), imagePath).Run(); err != nil {
		return fmt.Errorf("grow image: %w", err)
	}
	if output, err := exec.CommandContext(context.Background(), "resize2fs", imagePath).CombinedOutput(); err != nil {
		return fmt.Errorf("resize filesystem: %w: %s", err, output)
	}
	return nil
}

func MountReadOnly(imagePath, tempPattern string, allowJournalRecovery bool) (string, func(), error) {
	mountDir, err := paths.NewTempDir(tempPattern)
	if err != nil {
		return "", nil, err
	}

	options := []string{"loop,ro"}
	if allowJournalRecovery {
		options = append(options, "loop")
	}
	var mountErr error
	var mountOutput []byte
	for _, option := range options {
		cmd := exec.CommandContext(context.Background(), "sudo", "mount", "-o", option, imagePath, mountDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			mountErr = fmt.Errorf("mount -o %s: %w", option, err)
			mountOutput = output
			continue
		}
		cleanup := func() {
			_ = exec.CommandContext(context.Background(), "sudo", "umount", mountDir).Run()
			_ = os.RemoveAll(mountDir)
		}
		return mountDir, cleanup, nil
	}
	_ = os.RemoveAll(mountDir)
	return "", nil, fmt.Errorf("mount image: %w: %s", mountErr, mountOutput)
}

func EnsureDirs(imagePath string, dirs ...string) error {
	for _, dir := range dirs {
		if err := debugfsWrite(imagePath, "mkdir "+dir); err != nil {
			return err
		}
	}
	return nil
}

func WriteFile(imagePath, targetPath, sourcePath string) error {
	if err := RemoveFile(imagePath, targetPath); err != nil {
		return err
	}
	return debugfsWrite(imagePath, fmt.Sprintf("write %s %s", sourcePath, targetPath))
}

func RemoveFile(imagePath, targetPath string) error {
	cmd := exec.CommandContext(context.Background(), "debugfs", "-w", "-R", "rm "+targetPath, imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("debugfs remove %q: %w: %s", targetPath, err, output)
	}
	if strings.Contains(string(output), "File not found") {
		return nil
	}
	return nil
}

func ReadFile(imagePath, targetPath string) ([]byte, error) {
	tempFile, err := os.CreateTemp("", "keel-debugfs-*")
	if err != nil {
		return nil, err
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	defer func() {
		_ = os.Remove(tempPath)
	}()

	cmd := exec.CommandContext(context.Background(), "debugfs", "-R", fmt.Sprintf("dump %s %s", targetPath, tempPath), imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("debugfs dump %q: %w: %s", targetPath, err, output)
	}
	return os.ReadFile(tempPath)
}

func snapshotDirectory(source string) (string, error) {
	stageDir, err := paths.NewTempDir("keel-ext4-stage-*")
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

func debugfsWrite(imagePath, command string) error {
	cmd := exec.CommandContext(context.Background(), "debugfs", "-w", "-R", command, imagePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if isExistingPathMkdir(output) {
			return nil
		}
		return fmt.Errorf("debugfs %q: %w: %s", command, err, output)
	}
	return nil
}

func isExistingPathMkdir(output []byte) bool {
	text := string(output)
	return strings.Contains(text, "directory already exists")
}

func copySparseFile(dst, src *os.File, size int64) error {
	const chunkSize = 4 << 20

	if size == 0 {
		return nil
	}
	if err := dst.Truncate(size); err != nil {
		return err
	}
	if err := copySparseExtents(dst, src, size, chunkSize); err == nil {
		return nil
	} else if !isSparseSeekUnsupported(err) {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}
	_, err := io.CopyBuffer(dst, src, make([]byte, chunkSize))
	return err
}

func copySparseExtents(dst, src *os.File, size int64, chunkSize int) error {
	buf := make([]byte, chunkSize)
	offset := int64(0)
	for offset < size {
		dataOffset, err := unix.Seek(int(src.Fd()), offset, unix.SEEK_DATA)
		switch err {
		case nil:
		case unix.ENXIO:
			return nil
		default:
			return err
		}
		if dataOffset >= size {
			return nil
		}
		holeOffset, err := unix.Seek(int(src.Fd()), dataOffset, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if holeOffset > size {
			holeOffset = size
		}
		remaining := holeOffset - dataOffset
		if _, err := src.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		if _, err := dst.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		for remaining > 0 {
			chunk := int64(len(buf))
			if remaining < chunk {
				chunk = remaining
			}
			n := int(chunk)
			if _, err := io.ReadFull(src, buf[:n]); err != nil {
				return err
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= chunk
		}
		offset = holeOffset
	}
	return nil
}

func isSparseSeekUnsupported(err error) bool {
	return err == unix.ENXIO || err == unix.EINVAL || err == unix.ENOTSUP || err == unix.ENOSYS || err == unix.EOPNOTSUPP
}
