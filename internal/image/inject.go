package image

import (
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
	if err := debugfsWrite(rootfsPath, fmt.Sprintf("write %s /usr/local/bin/keel-agent", binaryPath)); err != nil {
		return err
	}
	if err := debugfsWrite(rootfsPath, fmt.Sprintf("write %s /etc/keel/init.sh", initPath)); err != nil {
		return err
	}
	return nil
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

func isExistingPathMkdir(output []byte) bool {
	text := string(output)
	return strings.Contains(text, "directory already exists")
}
