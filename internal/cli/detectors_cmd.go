package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
)

// newDetectorsCmd groups the read-only catalog commands. There is no way to
// add or change rules from the command line by design (see CONTRIBUTING.md on
// bounded adversarial parsing); the catalog is for transparency.
func newDetectorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detectors",
		Short: "Inspect the built-in detector catalog",
	}
	cmd.AddCommand(newDetectorsListCmd())
	return cmd
}

// detectorCatalog is the JSON document `detectors list --format json` prints.
type detectorCatalog struct {
	Count     int              `json:"count"`
	Detectors []detectors.Info `json:"detectors"`
}

func newDetectorsListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every detector id with its confidence tier, strategy and description",
		Long: "List the detector identifiers findings can carry in detector_name, with the confidence tier a match " +
			"carries before path and key context adjust it, the matching strategy and a one-line description. " +
			"docs/detectors.md is generated from the same data.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			infos := detectors.Default().Describe()
			switch strings.ToLower(strings.TrimSpace(format)) {
			case "table":
				return renderDetectorsTable(cmd.OutOrStdout(), infos)
			case "json":
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(detectorCatalog{Count: len(infos), Detectors: infos})
			default:
				return exitError{code: exitCodeFailure, message: fmt.Sprintf("unsupported output format %q: use table or json", format)}
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table or json")
	return cmd
}

// renderDetectorsTable prints the catalog as an aligned table. Every cell is
// built from compiled-in metadata, so no sanitising is needed.
func renderDetectorsTable(output io.Writer, infos []detectors.Info) error {
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tCONFIDENCE\tSTRATEGY\tDESCRIPTION"); err != nil {
		return err
	}
	for _, info := range infos {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", info.ID, info.Confidence, strings.Join(info.Strategies, ","), info.Description); err != nil {
			return err
		}
	}
	return writer.Flush()
}
