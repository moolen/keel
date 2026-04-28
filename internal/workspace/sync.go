package workspace

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/moolen/keel/internal/paths"
)

type SyncResult struct {
	Diff    Diff
	Applied bool
}

type SyncOptions struct {
	HostDir     string
	VMDir       string
	SyncDeletes bool
	Confirm     bool
	In          io.Reader
	Out         io.Writer
}

type ImageSyncOptions struct {
	HostDir     string
	ImagePath   string
	SyncDeletes bool
	Confirm     bool
	In          io.Reader
	Out         io.Writer
}

func SyncImage(opts ImageSyncOptions) (SyncResult, error) {
	vmDir, cleanup, err := mountImageReadOnly(opts.ImagePath)
	if err != nil {
		return SyncResult{}, err
	}
	defer cleanup()

	return SyncDirectories(SyncOptions{
		HostDir:     opts.HostDir,
		VMDir:       vmDir,
		SyncDeletes: opts.SyncDeletes,
		Confirm:     opts.Confirm,
		In:          opts.In,
		Out:         opts.Out,
	})
}

func SyncDirectories(opts SyncOptions) (SyncResult, error) {
	diff, err := DiffDirectories(opts.HostDir, opts.VMDir)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{Diff: diff}
	if diff.Empty() {
		return result, nil
	}

	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	printDiffSummary(out, diff)

	apply := true
	if opts.Confirm {
		apply, err = confirmSync(opts.In, out, diff)
		if err != nil {
			return result, err
		}
	}
	if !apply {
		return result, nil
	}
	if err := ApplyDiff(opts.HostDir, opts.VMDir, diff, opts.SyncDeletes); err != nil {
		return result, err
	}
	result.Applied = true
	return result, nil
}

func ApplyDiff(hostDir, vmDir string, diff Diff, syncDeletes bool) error {
	stagingRoot := filepath.Join(hostDir, ".keel-sync-tmp")
	if err := os.MkdirAll(stagingRoot, 0o755); err != nil {
		return err
	}
	for _, change := range append(append([]Change(nil), diff.Added...), diff.Modified...) {
		if err := copyIntoHost(stagingRoot, hostDir, vmDir, change.Path); err != nil {
			return err
		}
	}
	if syncDeletes {
		for _, change := range diff.Deleted {
			if err := os.RemoveAll(filepath.Join(hostDir, change.Path)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return os.RemoveAll(stagingRoot)
}

func mountImageReadOnly(imagePath string) (string, func(), error) {
	mountDir, err := paths.NewTempDir("keel-workspace-mount-*")
	if err != nil {
		return "", nil, err
	}

	// Prefer a read-only loop mount, but fall back to a writable mount when
	// ext4 requires journal recovery after the guest shuts down.
	var mountErr error
	var mountOutput []byte
	for _, options := range []string{"loop,ro", "loop"} {
		cmd := exec.CommandContext(context.Background(), "sudo", "mount", "-o", options, imagePath, mountDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			mountErr = fmt.Errorf("mount -o %s: %w", options, err)
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
	return "", nil, fmt.Errorf("mount workspace image: %w: %s", mountErr, mountOutput)
}

func printDiffSummary(w io.Writer, diff Diff) {
	_, _ = fmt.Fprintf(w,
		"Workspace changes detected:\n  modified: %d files\n  added:    %d files\n  deleted:  %d files\n",
		len(diff.Modified),
		len(diff.Added),
		len(diff.Deleted),
	)
}

func confirmSync(in io.Reader, out io.Writer, diff Diff) (bool, error) {
	if in == nil {
		in = os.Stdin
	}
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		return confirmSyncTerminal(file, out, diff)
	}
	return confirmSyncLineReader(in, out, diff)
}

func confirmSyncLineReader(in io.Reader, out io.Writer, diff Diff) (bool, error) {
	reader := bufio.NewReader(in)
	for {
		if _, err := fmt.Fprint(out, "Apply workspace changes? [y/N/d(iff)] "); err != nil {
			return false, err
		}
		answer, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		switch answer {
		case "y", "yes":
			return true, nil
		case "d", "diff":
			printDetailedDiff(out, diff)
		default:
			return false, nil
		}
		if err == io.EOF {
			return false, nil
		}
	}
}

func confirmSyncTerminal(in *os.File, out io.Writer, diff Diff) (bool, error) {
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = term.Restore(int(in.Fd()), state)
	}()

	reader := bufio.NewReader(in)
	for {
		if _, err := fmt.Fprint(out, "Apply workspace changes? [y/N/d(iff)] "); err != nil {
			return false, err
		}
		b, err := reader.ReadByte()
		if err != nil {
			return false, err
		}

		switch strings.ToLower(string(b)) {
		case "y":
			_, _ = fmt.Fprintln(out, "y")
			return true, nil
		case "d":
			_, _ = fmt.Fprintln(out, "d")
			printDetailedDiff(out, diff)
		case "\r", "\n", "n":
			if b == 'n' || b == 'N' {
				_, _ = fmt.Fprintln(out, string(b))
			} else {
				_, _ = fmt.Fprintln(out)
			}
			return false, nil
		default:
			// Keep the prompt strict and redraw on unknown keys.
		}
	}
}

func printDetailedDiff(w io.Writer, diff Diff) {
	for _, item := range diff.Modified {
		_, _ = fmt.Fprintf(w, "M %s\n", item.Path)
	}
	for _, item := range diff.Added {
		_, _ = fmt.Fprintf(w, "A %s\n", item.Path)
	}
	for _, item := range diff.Deleted {
		_, _ = fmt.Fprintf(w, "D %s\n", item.Path)
	}
}

func copyIntoHost(stagingRoot, hostDir, vmDir, rel string) error {
	sourcePath := filepath.Join(vmDir, rel)
	targetPath := filepath.Join(hostDir, rel)
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	stagePath := filepath.Join(stagingRoot, rel)
	if err := os.MkdirAll(filepath.Dir(stagePath), 0o755); err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(sourcePath)
		if err != nil {
			return err
		}
		_ = os.Remove(stagePath)
		if err := os.Symlink(linkTarget, stagePath); err != nil {
			return err
		}
	} else {
		if err := copyFile(sourcePath, stagePath, info.Mode().Perm()); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(stagePath, targetPath)
}
