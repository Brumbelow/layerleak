package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/brumbelow/layerleak/v3/internal/version"
)

// newVersionCmd prints build details. The first text line matches the output
// of `layerleak --version`, which stays available as an alias.
func newVersionCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit, build time and toolchain of this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Describe()
			switch format {
			case "text":
				out := cmd.OutOrStdout()
				_, err := fmt.Fprintf(out, "layerleak version %s\ncommit: %s%s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n",
					info.Version, info.Commit, modifiedSuffix(info), info.BuildTime, info.GoVersion, info.OS, info.Arch)
				return err
			case "json":
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(info)
			default:
				return exitError{code: 1, message: fmt.Sprintf("unsupported output format %q: use text or json", format)}
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text or json")
	return cmd
}

func modifiedSuffix(info version.Info) string {
	if info.Modified {
		return " (modified)"
	}
	return ""
}
