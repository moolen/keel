package cli

import "github.com/spf13/cobra"

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect or initialize keel configuration",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "show", Short: "Show resolved configuration"},
		&cobra.Command{Use: "init", Short: "Create a starter keel.yaml"},
	)
	return cmd
}
