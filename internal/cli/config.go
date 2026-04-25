package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/moolen/keel/internal/config"
)

const starterConfig = `image: ubuntu:24.04

resources:
  vcpu: 2
  memory_mb: 2048
  disk_mb: 4096

workspace:
  mount: .
  target: /workspace
  sync_back: false
  sync_deletes: false
  sync_confirm: true

network:
  mode: vsock
  deny_if_no_sni: false
  dns:
    allowed:
      - "*.github.com"
  tcp:
    allowed_cidrs: []
    denied_cidrs: []
  tls:
    allowed_sni:
      - "*.github.com"

features:
  - name: docker
    config:
      storage_driver: overlay2

env:
  TERM: xterm-256color
`

func newConfigCommand(deps Dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect or initialize keel configuration",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Show resolved configuration",
			RunE: func(cmd *cobra.Command, _ []string) error {
				loadConfig := deps.LoadConfig
				if loadConfig == nil {
					loadConfig = func(_ context.Context, opts config.LoadOptions) (config.Config, error) {
						return config.Load(opts)
					}
				}

				wd, err := os.Getwd()
				if err != nil {
					return err
				}
				cfg, err := loadConfig(cmd.Context(), config.LoadOptions{WorkingDir: wd})
				if err != nil {
					return fmt.Errorf("load config: %w", err)
				}

				data, err := yaml.Marshal(cfg)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(data)
				return err
			},
		},
		&cobra.Command{
			Use:   "init",
			Short: "Create a starter keel.yaml",
			RunE: func(cmd *cobra.Command, _ []string) error {
				path := "keel.yaml"
				if _, err := os.Stat(path); err == nil {
					return errors.New("keel.yaml already exists")
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if err := os.WriteFile(path, []byte(starterConfig), 0o644); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "wrote keel.yaml")
				return err
			},
		},
	)
	return cmd
}
