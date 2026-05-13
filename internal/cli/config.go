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

kernel:
  source: release://latest

resources:
  vcpu: 2
  memory_mb: 2048
  disk_mb: 4096
  # optional: grow the VM root disk beyond the image default
  # root_disk_mb: 8192

workspace:
  mount: .
  target: /workspace
  sync_back: false
  sync_deletes: false
  sync_confirm: true

network:
  mode: vsock
  audit: false
  endpoints:
    - host: api.github.com
      port: 443
      tls:
        require_sni_match: true
      mitm:
        required: true
      http:
        default: deny
        rules:
          - action: allow
            methods: ["GET"]
            paths: ["/repos/*", "/rate_limit"]
    - host: auth.docker.io
      port: 443
      tls:
        require_sni_match: true
  ip_rules: []
  mitm:
    ca:
      name: keel-local-ca
      install_system: true
      install_docker: true

features:
  - name: docker
    config:
      storage_driver: overlay2

env:
  static:
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
