package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
					puller := image.Puller{GuestInit: defaultGuestAgentAssets}
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
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", cached.Reference, formatBytes(cached.SizeBytes)); err != nil {
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

func defaultGuestAgentAssets() (image.GuestAgentAssets, error) {
	execPath, err := os.Executable()
	if err != nil {
		return image.GuestAgentAssets{}, err
	}
	return loadGuestAgentAssets(execPath, os.ReadFile)
}

func loadGuestAgentAssets(execPath string, readFile func(string) ([]byte, error)) (image.GuestAgentAssets, error) {
	candidates := []string{
		filepath.Join(filepath.Dir(execPath), "..", "dist", "keel-agent"),
		filepath.Join(filepath.Dir(execPath), "dist", "keel-agent"),
	}
	for _, candidate := range candidates {
		data, err := readFile(candidate)
		if err == nil {
			return image.GuestAgentAssets{
				Binary:     data,
				InitScript: "#!/bin/sh\nexec /usr/local/bin/keel-agent\n",
			}, nil
		}
		if !os.IsNotExist(err) {
			return image.GuestAgentAssets{}, err
		}
	}
	return image.GuestAgentAssets{}, fmt.Errorf(
		"guest agent binary not found; looked in %s. build it with `make guest-agent` before pulling or running images",
		strings.Join(candidates, ", "),
	)
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

func formatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	value := float64(size)
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, suffix := range suffixes {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", value/unit)
}
