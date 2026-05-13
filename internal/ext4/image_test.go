package ext4

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCopySparseFilePreservesLogicalSize(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.ext4")
	targetPath := filepath.Join(tempDir, "target.ext4")

	src, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	const logicalSize = int64(1 << 30)
	if err := src.Truncate(logicalSize); err != nil {
		t.Fatalf("Truncate() error = %v", err)
	}
	if _, err := src.WriteAt([]byte("keel"), 0); err != nil {
		t.Fatalf("WriteAt(start) error = %v", err)
	}
	if _, err := src.WriteAt([]byte("agent"), logicalSize-int64(len("agent"))); err != nil {
		t.Fatalf("WriteAt(end) error = %v", err)
	}
	if err := src.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := CopySparseFile(sourcePath, targetPath); err != nil {
		t.Fatalf("CopySparseFile() error = %v", err)
	}

	srcInfo, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatalf("Stat(source) error = %v", err)
	}
	dstInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if got, want := dstInfo.Size(), srcInfo.Size(); got != want {
		t.Fatalf("target size = %d, want %d", got, want)
	}

	srcBlocks := statBlocks(t, srcInfo)
	dstBlocks := statBlocks(t, dstInfo)
	if srcBlocks == 0 || dstBlocks == 0 {
		t.Skip("filesystem does not report sparse allocation blocks")
	}
	if dstBlocks > srcBlocks*4 {
		t.Fatalf("target blocks = %d, want sparse copy close to source blocks %d", dstBlocks, srcBlocks)
	}
}

func TestSnapshotDirectoryCopiesRegularFilesAndSymlinks(t *testing.T) {
	sourceDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourceDir, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "nested", "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("nested/file.txt", filepath.Join(sourceDir, "file.link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	stageDir, err := snapshotDirectory(sourceDir)
	if err != nil {
		t.Fatalf("snapshotDirectory() error = %v", err)
	}
	defer os.RemoveAll(stageDir)

	data, err := os.ReadFile(filepath.Join(stageDir, "nested", "file.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("staged file = %q, want hello", string(data))
	}
	linkTarget, err := os.Readlink(filepath.Join(stageDir, "file.link"))
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if linkTarget != "nested/file.txt" {
		t.Fatalf("link target = %q, want nested/file.txt", linkTarget)
	}
}

func TestCreateImageCanUseSourceDirDirectlyWithReadOnlyDirectories(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is required for ext4 image tests")
	}

	sourceDir := t.TempDir()
	readOnlyDir := filepath.Join(sourceDir, "usr", "share", "readonly")
	if err := os.MkdirAll(readOnlyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(readOnlyDir, "payload.txt"), []byte("keel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatalf("Chmod(read-only) error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(readOnlyDir, 0o755)
	})

	imagePath := filepath.Join(t.TempDir(), "rootfs.ext4")
	result, err := CreateImage(CreateOptions{
		SourceDir:      sourceDir,
		ImagePath:      imagePath,
		SizeMB:         128,
		Label:          "rootfs",
		StageSourceDir: false,
	})
	if err != nil {
		t.Fatalf("CreateImage() error = %v", err)
	}
	if result.ImagePath != imagePath {
		t.Fatalf("result.ImagePath = %q, want %q", result.ImagePath, imagePath)
	}
}

func TestMountReadOnlyFallsBackToWritableLoopMount(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "sudo.log")
	scriptPath := filepath.Join(binDir, "sudo")
	script := fmt.Sprintf(`#!/bin/sh
printf "%%s\n" "$*" >> %q
if [ "$1" = "mount" ] && [ "$2" = "-o" ] && [ "$3" = "loop,ro" ]; then
  exit 1
fi
exit 0
`, logPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	mountDir, cleanup, err := MountReadOnly(filepath.Join(t.TempDir(), "workspace.ext4"), "keel-workspace-mount-*", true)
	if err != nil {
		t.Fatalf("MountReadOnly() error = %v", err)
	}
	cleanup()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if got, want := len(lines), 3; got != want {
		t.Fatalf("logged commands = %#v, want %d entries", lines, want)
	}
	if !strings.Contains(lines[0], "mount -o loop,ro") {
		t.Fatalf("first command = %q, want readonly loop mount attempt", lines[0])
	}
	if !strings.Contains(lines[1], "mount -o loop ") {
		t.Fatalf("second command = %q, want writable loop mount fallback", lines[1])
	}
	if got, want := lines[2], "umount "+mountDir; got != want {
		t.Fatalf("cleanup command = %q, want %q", got, want)
	}
}

func statBlocks(t *testing.T, info os.FileInfo) int64 {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("stat blocks unavailable")
	}
	return stat.Blocks
}
