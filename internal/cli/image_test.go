package cli

import (
	"bytes"
	"context"
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
