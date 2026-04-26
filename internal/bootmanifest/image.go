package bootmanifest

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func WriteImage(path string, manifest pkgboot.Manifest) error {
	stageDir, err := os.MkdirTemp("", "keel-bootmanifest-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stageDir) }()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stageDir, "boot.json"), data, 0o644); err != nil {
		return err
	}
	_, err = workspace.PrepareImage(workspace.PrepareOptions{
		SourceDir: stageDir,
		ImagePath: path,
		SizeMB:    8,
		Label:     "bootmeta",
	})
	return err
}
