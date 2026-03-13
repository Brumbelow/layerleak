package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "scanner",
		Short:         "Scan public Docker Hub images for likely secrets",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(newScanCmd())

	return cmd
}
