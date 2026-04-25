package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
)

type Dependencies struct {
	Runner     Runner
	LoadConfig func(context.Context, config.LoadOptions) (config.Config, error)
	PullImage  func(context.Context, string, string) (image.PullResult, error)
}

func NewRootCommand(deps Dependencies) *cobra.Command {
	var image string
	var verbose bool
	var dryRun bool

	root := &cobra.Command{
		Use:           "keel",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			loadConfig := deps.LoadConfig
			if loadConfig == nil {
				loadConfig = func(_ context.Context, opts config.LoadOptions) (config.Config, error) {
					return config.Load(opts)
				}
			}

			cfg, err := loadConfig(cmd.Context(), config.LoadOptions{WorkingDir: wd})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			cfg = config.ApplyOverrides(cfg, config.OverrideConfig{
				Image:   image,
				Command: args,
				Verbose: verbose,
				DryRun:  dryRun,
			})

			runner := deps.Runner
			if runner == nil {
				runner = NopRunner{}
			}
			return runner.Run(cmd.Context(), RunRequest{
				Config:  cfg,
				Command: args,
				Stdin:   cmd.InOrStdin(),
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
			})
		},
	}

	root.Flags().StringVar(&image, "image", "", "override the OCI image reference")
	root.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
	root.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without booting a VM")
	root.AddCommand(newImageCommand(deps), newConfigCommand(deps))
	return root
}
