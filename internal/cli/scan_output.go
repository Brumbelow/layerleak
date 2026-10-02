package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/sarif"
)

// writeFormattedOutput renders to stdout, or to the --output file when one is
// named ("-" and "" mean stdout).
func writeFormattedOutput(stdout io.Writer, outputPath string, render func(io.Writer) error) error {
	path := strings.TrimSpace(outputPath)
	if path == "" || path == "-" {
		return render(stdout)
	}
	return writeOutputFile(path, render)
}

func parseOutputFormat(value string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "summary", "json", "sarif":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported output format %q: use summary, json, or sarif", value)
	}
}

// renderSARIF writes the result as a SARIF 2.1.0 log. The rule list comes
// from the default detector catalog so every detector is described (with the
// catalog description) even when it produced no result, and
// tool.driver.version is this binary's version. Baselined findings carry
// the baseline entry's reason as their suppression justification.
func renderSARIF(out io.Writer, result jobs.Result, accepted *baseline) error {
	options := sarif.Options{
		ToolVersion: effectiveVersion(),
		Rules:       sarifRules(detectors.Default().Describe()),
	}
	if accepted != nil {
		options.Justification = accepted.justification
	}
	return sarif.Encode(out, sarif.FromResult(result, options))
}

func sarifRules(catalog []detectors.Info) []sarif.Rule {
	rules := make([]sarif.Rule, 0, len(catalog))
	for _, info := range catalog {
		rules = append(rules, sarif.Rule{ID: info.ID, Description: info.Description})
	}
	return rules
}
