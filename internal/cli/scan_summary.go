package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

func renderSummary(output io.Writer, result jobs.Result) error {
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	for _, row := range summaryRows(result) {
		if _, err := fmt.Fprintf(writer, "%s:\t%v\n", row.label, row.value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}
	if err := renderSummaryTargets(writer, result); err != nil {
		return err
	}
	if err := renderSummaryFindings(writer, result); err != nil {
		return err
	}
	return writer.Flush()
}

// summaryFindingsCap bounds the findings table so a noisy image does not
// scroll the counts off the terminal; the JSON output carries them all.
const summaryFindingsCap = 50

// renderSummaryFindings lists the actionable findings (detector, confidence,
// location, redacted value, platform). Every cell is sanitised because
// paths, keys and redacted values come from the image.
func renderSummaryFindings(writer io.Writer, result jobs.Result) error {
	if len(result.Findings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Detector\tConfidence\tLocation\tRedacted Value\tPlatform"); err != nil {
		return err
	}
	shown := min(len(result.Findings), summaryFindingsCap)
	for _, item := range result.Findings[:shown] {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			sanitizeProgressValue(item.DetectorName),
			sanitizeProgressValue(item.Confidence),
			sanitizeProgressValue(findingLocation(item)),
			sanitizeProgressValue(item.RedactedValue),
			sanitizeProgressValue(item.Platform.String()),
		); err != nil {
			return err
		}
	}
	if remaining := len(result.Findings) - shown; remaining > 0 {
		if _, err := fmt.Fprintf(writer, "and %d more\n", remaining); err != nil {
			return err
		}
	}
	return nil
}

// findingLocation is file_path[:line] for file findings and source_type:key
// for image metadata findings.
func findingLocation(item findings.Finding) string {
	if item.FilePath != "" {
		if item.LineNumber > 0 {
			return fmt.Sprintf("%s:%d", item.FilePath, item.LineNumber)
		}
		return item.FilePath
	}
	if item.Key != "" {
		return string(item.SourceType) + ":" + item.Key
	}
	return string(item.SourceType)
}

type summaryRow struct {
	label string
	value any
}

// summaryRows lists the counters. suppressed_findings_count includes the
// baselined findings; the summary shows the two groups separately.
func summaryRows(result jobs.Result) []summaryRow {
	baselined := countBaselined(result.SuppressedFindings)
	rows := []summaryRow{
		{"Requested Reference", sanitizeProgressValue(result.RequestedReference)},
		{"Repository", sanitizeProgressValue(result.Repository)},
		{"Status", result.Status},
	}
	if result.ResolvedReference != "" {
		rows = append(rows, summaryRow{"Resolved Reference", sanitizeProgressValue(result.ResolvedReference)})
	}
	if result.RequestedDigest != "" {
		rows = append(rows, summaryRow{"Requested Digest", sanitizeProgressValue(result.RequestedDigest)})
	}
	if result.TagsEnumerated > 0 || result.Mode == "repository" {
		rows = append(rows,
			summaryRow{"Tags Enumerated", result.TagsEnumerated},
			summaryRow{"Tags Resolved", result.TagsResolved},
			summaryRow{"Tags Failed", result.TagsFailed},
		)
	}
	return append(rows,
		summaryRow{"Targets Selected", result.TargetCount},
		summaryRow{"Targets Completed", result.CompletedTargetCount},
		summaryRow{"Targets Partial", result.PartialTargetCount},
		summaryRow{"Targets Failed", result.FailedTargetCount},
		summaryRow{"Manifests Selected", result.ManifestCount},
		summaryRow{"Manifests Completed", result.CompletedManifestCount},
		summaryRow{"Manifests Failed", result.FailedManifestCount},
		summaryRow{"Coverage Complete", result.Coverage.Complete},
		summaryRow{"Files Scanned", result.Coverage.FilesScanned},
		summaryRow{"Files Skipped Oversize", result.Coverage.FilesSkippedOversize},
		summaryRow{"Total Findings", result.TotalFindings},
		summaryRow{"Unique Fingerprints", result.UniqueFingerprints},
		summaryRow{"Suppressed Example Findings", max(result.SuppressedFindingsCount-baselined, 0)},
		summaryRow{"Baselined Findings", baselined},
	)
}

func renderSummaryTargets(writer io.Writer, result jobs.Result) error {
	if result.Mode == "reference" && len(result.Targets) == 1 {
		if _, err := fmt.Fprintln(writer, "Platform\tManifest Digest\tFindings\tStatus"); err != nil {
			return err
		}
		for _, item := range result.Targets[0].PlatformResults {
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", sanitizeProgressValue(item.Platform.String()), sanitizeProgressValue(item.ManifestDigest), item.FindingsCount, summaryItemStatus(item.Error)); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := fmt.Fprintln(writer, "Reference\tTags\tFindings\tStatus"); err != nil {
		return err
	}
	for _, item := range result.Targets {
		if _, err := fmt.Fprintf(writer, "%s\t%d\t%d\t%s\n", sanitizeProgressValue(targetReferenceLabel(item)), len(item.Tags), item.FindingsCount, summaryItemStatus(item.Error)); err != nil {
			return err
		}
	}
	return nil
}

func summaryItemStatus(message string) string {
	if message == "" {
		return "ok"
	}
	return sanitizeProgressValue(message)
}

func targetReferenceLabel(item jobs.TargetResult) string {
	if item.ResolvedReference != "" {
		return item.ResolvedReference
	}
	return item.Reference
}
