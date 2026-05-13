package image

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moolen/keel/internal/ext4"
)

type GuestAgentAssets struct {
	Binary     []byte
	InitScript string
}

type GuestTrustAssets struct {
	Enabled   bool
	CACertPEM []byte
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
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	binaryPath := filepath.Join(tempDir, "keel-agent")
	if err := os.WriteFile(binaryPath, assets.Binary, 0o755); err != nil {
		return err
	}
	initPath := filepath.Join(tempDir, "init.sh")
	if err := os.WriteFile(initPath, []byte(assets.InitScript), 0o755); err != nil {
		return err
	}

	if err := ext4.EnsureDirs(rootfsPath, "/usr", "/usr/local", "/usr/local/bin", "/etc", "/etc/keel"); err != nil {
		return err
	}
	if err := ext4.WriteFile(rootfsPath, "/usr/local/bin/keel-agent", binaryPath); err != nil {
		return err
	}
	if err := ext4.WriteFile(rootfsPath, "/etc/keel/init.sh", initPath); err != nil {
		return err
	}
	return nil
}

func InjectGuestTrust(rootfsPath string, assets GuestTrustAssets) error {
	if !assets.Enabled || len(assets.CACertPEM) == 0 {
		return nil
	}
	if rootfsPath == "" {
		return fmt.Errorf("rootfs path is required")
	}

	tempDir, err := os.MkdirTemp("", "keel-trust-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	certPath := filepath.Join(tempDir, "keel-local-ca.crt")
	if err := os.WriteFile(certPath, assets.CACertPEM, 0o644); err != nil {
		return err
	}
	scriptPath := filepath.Join(tempDir, "install-ca.sh")
	if err := os.WriteFile(scriptPath, []byte(`#!/bin/sh
set -eu
if command -v update-ca-certificates >/dev/null 2>&1; then
	update-ca-certificates
fi
`), 0o755); err != nil {
		return err
	}

	if err := ext4.EnsureDirs(rootfsPath,
		"/usr",
		"/usr/local",
		"/usr/local/share",
		"/usr/local/share/ca-certificates",
		"/etc",
		"/etc/keel",
	); err != nil {
		return err
	}
	if err := ext4.WriteFile(rootfsPath, "/usr/local/share/ca-certificates/keel-local-ca.crt", certPath); err != nil {
		return err
	}
	if err := ext4.WriteFile(rootfsPath, "/etc/keel/install-ca.sh", scriptPath); err != nil {
		return err
	}
	for _, bundlePath := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/cert.pem",
	} {
		if err := appendPEMToExt4FileIfPresent(rootfsPath, bundlePath, assets.CACertPEM); err != nil {
			return err
		}
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

func appendPEMToExt4FileIfPresent(rootfsPath, targetPath string, data []byte) error {
	existing, err := ext4.ReadFile(rootfsPath, targetPath)
	if err != nil {
		if strings.Contains(err.Error(), "File not found") {
			return nil
		}
		return err
	}
	if bytes.Contains(existing, data) {
		return nil
	}

	tempDir, err := os.MkdirTemp("", "keel-trust-bundle-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	combined := append(append(bytes.TrimRight(existing, "\n"), '\n'), data...)
	if len(combined) == 0 || combined[len(combined)-1] != '\n' {
		combined = append(combined, '\n')
	}
	tempPath := filepath.Join(tempDir, "bundle.pem")
	if err := os.WriteFile(tempPath, combined, 0o644); err != nil {
		return err
	}
	return ext4.WriteFile(rootfsPath, targetPath, tempPath)
}

func rootfsGuestAgentMatches(rootfsPath, wantDigest string) (bool, error) {
	data, err := ext4.ReadFile(rootfsPath, "/usr/local/bin/keel-agent")
	if err != nil {
		if strings.Contains(err.Error(), "File not found") {
			return false, nil
		}
		return false, err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]) == wantDigest, nil
}
