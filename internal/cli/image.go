package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
)

func newImageCommand(deps Dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Manage cached OCI images",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "pull <ref>",
			Short: "Pull and cache an image",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadCLIConfig(cmd.Context(), deps)
				if err != nil {
					return err
				}
				pull := deps.PullImage
				if pull == nil {
					puller := image.Puller{}
					pull = puller.PullAndCache
				}
				result, err := pull(cmd.Context(), cfg.ImageCacheDir, args[0])
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "cached %s in %s\n", args[0], result.Layout.Directory)
				return err
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List cached images",
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := loadCLIConfig(cmd.Context(), deps)
				if err != nil {
					return err
				}
				images, err := image.ListCachedImages(cfg.ImageCacheDir)
				if err != nil {
					return err
				}
				for _, cached := range images {
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), cached.Reference); err != nil {
						return err
					}
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "rm <ref>",
			Short: "Remove a cached image",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadCLIConfig(cmd.Context(), deps)
				if err != nil {
					return err
				}
				if err := image.RemoveCachedImage(cfg.ImageCacheDir, args[0]); err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
				return err
			},
		},
	)
	return cmd
}

func loadCLIConfig(ctx context.Context, deps Dependencies) (config.Config, error) {
	loadConfig := deps.LoadConfig
	if loadConfig == nil {
		loadConfig = func(_ context.Context, opts config.LoadOptions) (config.Config, error) {
			return config.Load(opts)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := loadConfig(ctx, config.LoadOptions{WorkingDir: wd})
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}
