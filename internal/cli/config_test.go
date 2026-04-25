package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
)

func TestConfigShowRendersResolvedConfig(t *testing.T) {
	var stdout bytes.Buffer

	cmd := NewRootCommand(Dependencies{
		LoadConfig: func(_ context.Context, _ config.LoadOptions) (config.Config, error) {
			cfg := config.Default()
			cfg.Image = "alpine:3.21"
			return cfg, nil
		},
	})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"config", "show"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "image: alpine:3.21") {
		t.Fatalf("output = %q, want rendered image", output)
	}
}

func TestConfigInitWritesStarterFile(t *testing.T) {
	var stdout bytes.Buffer
	wd := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("Chdir(%q) error = %v", wd, err)
	}

	cmd := NewRootCommand(Dependencies{})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"config", "init"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(wd, "keel.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(keel.yaml) error = %v", err)
	}
	if !strings.Contains(string(data), "image: ubuntu:24.04") {
		t.Fatalf("starter config missing image: %q", string(data))
	}
}
