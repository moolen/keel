package image

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type GuestAgentAssets struct {
	Binary     []byte
	InitScript string
}

func (a GuestAgentAssets) Digest() string {
	sum := sha256.Sum256(a.Binary)
	return fmt.Sprintf("%x", sum[:])
}

func InjectGuestAgent(rootfsPath string, assets GuestAgentAssets) error {
	if rootfsPath == "" {
		return fmt.Errorf("rootfs path is required")
	}
	if len(assets.Binary) == 0 {
		return fmt.Errorf("guest agent binary is required")
	}
	if assets.InitScript == "" {
		assets.InitScript = "#!/bin/sh\nexec /usr/local/bin/keel-agent\n"
	}

	tempDir, err := os.MkdirTemp("", "keel-inject-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	binaryPath := filepath.Join(tempDir, "keel-agent")
	if err := os.WriteFile(binaryPath, assets.Binary, 0o755); err != nil {
		return err
	}
	initPath := filepath.Join(tempDir, "init.sh")
	if err := os.WriteFile(initPath, []byte(assets.InitScript), 0o755); err != nil {
		return err
	}

	for _, dir := range []string{"/usr", "/usr/local", "/usr/local/bin", "/etc", "/etc/keel"} {
		if err := debugfsWrite(rootfsPath, "mkdir "+dir); err != nil {
			return err
		}
	}
	for _, target := range []string{"/usr/local/bin/keel-agent", "/etc/keel/init.sh"} {
		if err := debugfsRemove(rootfsPath, target); err != nil {
			return err
		}
	}
	if err := debugfsWrite(rootfsPath, fmt.Sprintf("write %s /usr/local/bin/keel-agent", binaryPath)); err != nil {
		return err
	}
	if err := debugfsWrite(rootfsPath, fmt.Sprintf("write %s /etc/keel/init.sh", initPath)); err != nil {
		return err
	}
	return nil
}

func EnsureGuestAgent(rootfsPath, digestPath string, assets GuestAgentAssets) (bool, error) {
	if rootfsPath == "" {
		return false, fmt.Errorf("rootfs path is required")
	}
	if digestPath == "" {
		return false, fmt.Errorf("guest agent digest path is required")
	}
	currentDigest := assets.Digest()
	data, err := os.ReadFile(digestPath)
	if err == nil && strings.TrimSpace(string(data)) == currentDigest {
		matches, matchErr := rootfsGuestAgentMatches(rootfsPath, currentDigest)
		if matchErr != nil {
			return false, matchErr
		}
		if matches {
			return false, nil
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := InjectGuestAgent(rootfsPath, assets); err != nil {
		return false, err
	}
	if err := os.WriteFile(digestPath, []byte(currentDigest+"\n"), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func debugfsWrite(rootfsPath, command string) error {
	cmd := exec.Command("debugfs", "-w", "-R", command, rootfsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if isExistingPathMkdir(output) {
			return nil
		}
		return fmt.Errorf("debugfs %q: %w: %s", command, err, output)
	}
	return nil
}

func debugfsRemove(rootfsPath, target string) error {
	cmd := exec.Command("debugfs", "-w", "-R", "rm "+target, rootfsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("debugfs remove %q: %w: %s", target, err, output)
	}
	if strings.Contains(string(output), "File not found") {
		return nil
	}
	return nil
}

func rootfsGuestAgentMatches(rootfsPath, wantDigest string) (bool, error) {
	data, err := debugfsReadFile(rootfsPath, "/usr/local/bin/keel-agent")
	if err != nil {
		if strings.Contains(err.Error(), "File not found") {
			return false, nil
		}
		return false, err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]) == wantDigest, nil
}

func debugfsReadFile(rootfsPath, target string) ([]byte, error) {
	tempFile, err := os.CreateTemp("", "keel-debugfs-*")
	if err != nil {
		return nil, err
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	defer os.Remove(tempPath)

	cmd := exec.Command("debugfs", "-R", fmt.Sprintf("dump %s %s", target, tempPath), rootfsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("debugfs dump %q: %w: %s", target, err, output)
	}
	return os.ReadFile(tempPath)
}

func isExistingPathMkdir(output []byte) bool {
	text := string(output)
	return strings.Contains(text, "directory already exists")
}
