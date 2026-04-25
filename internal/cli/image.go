package cli

import "github.com/spf13/cobra"

func newImageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Manage cached OCI images",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "pull <ref>", Short: "Pull and cache an image"},
		&cobra.Command{Use: "list", Short: "List cached images"},
		&cobra.Command{Use: "rm <ref>", Short: "Remove a cached image"},
	)
	return cmd
}
