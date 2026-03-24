package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Run() int {
	if err := newRootCmd().Execute(); err != nil {
		var coded interface {
			ExitCode() int
		}
		if errors.As(err, &coded) {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, err)
			}
			return coded.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "layerleak",
		Short:         "Scan public Docker Hub images for likely secrets",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(newScanCmd())

	return cmd
}
