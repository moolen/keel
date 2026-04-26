package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
)

func TestImagePullCommandInvokesPuller(t *testing.T) {
	var stdout bytes.Buffer
	var gotRef string
	var gotCacheDir string

	cmd := NewRootCommand(Dependencies{
		LoadConfig: func(_ context.Context, _ config.LoadOptions) (config.Config, error) {
			cfg := config.Default()
			cfg.ImageCacheDir = "/tmp/keel-cache"
			return cfg, nil
		},
		PullImage: func(_ context.Context, cacheDir, ref string) (image.PullResult, error) {
			gotCacheDir = cacheDir
			gotRef = ref
			return image.PullResult{
				Layout: image.CacheLayout{
					Directory: "/tmp/keel-cache/index.docker.io/library/ubuntu/24.04",
				},
			}, nil
		},
	})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"image", "pull", "ubuntu:24.04"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if gotRef != "ubuntu:24.04" || gotCacheDir != "/tmp/keel-cache" {
		t.Fatalf("unexpected pull args: ref=%q cache=%q", gotRef, gotCacheDir)
	}
	if !strings.Contains(stdout.String(), "/tmp/keel-cache") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestLoadGuestAgentAssetsReturnsBuildHint(t *testing.T) {
	_, err := loadGuestAgentAssets("/tmp/keel/bin/keel", func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	})
	if err == nil {
		t.Fatal("loadGuestAgentAssets() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "make guest-agent") {
		t.Fatalf("error = %q, want build hint", err)
	}
	if !strings.Contains(err.Error(), "dist/keel-agent") {
		t.Fatalf("error = %q, want searched path hint", err)
	}
}

func TestImageListCommandPrintsReferenceAndSize(t *testing.T) {
	tmpHome := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".config", "keel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "keel.yaml"), []byte("image_cache_dir: "+filepath.Join(projectDir, "cache")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rootfsPath := filepath.Join(projectDir, "cache", "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := NewRootCommand(Dependencies{})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"image", "list"})
	t.Chdir(projectDir)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "index.docker.io/library/ubuntu:24.04") {
		t.Fatalf("output = %q, want listed reference", output)
	}
	if !strings.Contains(output, "11 B") {
		t.Fatalf("output = %q, want size column", output)
	}
}
