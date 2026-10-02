package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// defaultBaselineFileName is where `baseline create` writes unless --output
// names another file.
const defaultBaselineFileName = "layerleak-baseline.json"

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Create baseline files that accept reviewed findings by fingerprint",
	}
	cmd.AddCommand(newBaselineCreateCmd(time.Now))
	return cmd
}

// newBaselineCreateCmd writes a baseline file from a result (--format json
// output) or a scan record. Every actionable finding becomes an entry with
// its fingerprint and detector; nothing else is copied from the source.
func newBaselineCreateCmd(now func() time.Time) *cobra.Command {
	var from string
	var output string
	var reason string
	var force bool
	cmd := &cobra.Command{
		Use:   "create --from <result.json>",
		Short: "Write a baseline file listing every actionable finding of a scan result",
		Long: "Read a result (layerleak scan --format json) or a scan record and write a baseline file with one entry " +
			"per actionable finding: its fingerprint and detector plus the reason. Pass the file to later scans with " +
			"--baseline; matched findings are reported with disposition baselined and no longer produce exit code 2. " +
			"Only fingerprints and detector names are written, never values.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(from) == "" {
				return exitError{code: exitCodeFailure, message: "--from is required: the result JSON or scan record to baseline"}
			}
			text := strings.TrimSpace(reason)
			if text == "" {
				text = "baselined on " + now().UTC().Format("2006-01-02")
			}
			if len(text) > maxBaselineReasonBytes {
				return exitError{code: exitCodeFailure, message: fmt.Sprintf("--reason exceeds %d bytes", maxBaselineReasonBytes)}
			}
			source, err := os.Open(from) //nolint:gosec // the operator-chosen --from path
			if err != nil {
				return exitError{code: exitCodeFailure, message: fmt.Sprintf("open --from file: %v", err)}
			}
			document, err := baselineFromSource(source, text)
			_ = source.Close()
			if err != nil {
				return exitError{code: exitCodeFailure, message: fmt.Sprintf("--from file %q: %v", from, err)}
			}
			target := strings.TrimSpace(output)
			if target == "-" {
				return encodeBaseline(cmd.OutOrStdout(), document)
			}
			if target == "" {
				target = defaultBaselineFileName
			}
			if err := writeBaselineFile(target, document, force); err != nil {
				return exitError{code: exitCodeFailure, message: err.Error()}
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Baseline: %d entries written to %q\n", len(document.Entries), target)
			return err
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "Result JSON (layerleak scan --format json) or scan record to read the actionable findings from")
	cmd.Flags().StringVar(&output, "output", defaultBaselineFileName, "Baseline file to write; - means stdout. Created with mode 0600 and never overwritten without --force.")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason recorded on every entry (default: \"baselined on <date>\")")
	cmd.Flags().BoolVar(&force, "force", false, "Replace an existing baseline file")
	return cmd
}
