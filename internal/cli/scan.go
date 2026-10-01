package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
	"github.com/brumbelow/layerleak/v3/internal/storage"
	"github.com/spf13/cobra"
)

const repositorySweepWarning = "warning: --all-tags enumerates every public tag in the repository and may scan many distinct images" //nolint:gosec // user-facing warning text, not a credential

func newScanCmd() *cobra.Command {
	return newScanCmdWithStore(newStore)
}

func newScanCmdWithStore(openStore func(config.Config) (storage.Store, error)) *cobra.Command {
	var platform string
	var format string
	var tagPageSize int
	var maxRepositoryTags int
	var maxRepositoryTargets int
	var allTags bool
	var allowPartial bool
	var progressSetting string
	var outputDir string
	var outputPath string
	var noArtifacts bool
	var noDatabase bool
	var failOn string

	cmd := &cobra.Command{
		Use:   "scan <image-ref>",
		Short: "Scan a public OCI image reference from any supported registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFormat, err := parseOutputFormat(format)
			if err != nil {
				return err
			}
			progressMode, err := parseProgressMode(progressSetting)
			if err != nil {
				return err
			}
			failThreshold, err := parseFailOn(failOn)
			if err != nil {
				return err
			}
			ref, err := manifest.ParseReference(args[0])
			if err != nil {
				return err
			}
			if strings.TrimSpace(platform) != "" {
				if _, err := manifest.ParsePlatformSelector(platform); err != nil {
					return fmt.Errorf("invalid --platform: %w", err)
				}
			}
			if allTags && !ref.IsRepositoryOnly() {
				return fmt.Errorf("--all-tags requires a bare repository reference")
			}
			if err := validateRepositoryScopeFlags(cmd, allTags); err != nil {
				return err
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := applyScanScopeFlags(cmd, &cfg, tagPageSize, maxRepositoryTags, maxRepositoryTargets); err != nil {
				return err
			}
			logger, err := newLogger(cfg.LogLevel, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			progressMode = effectiveProgressMode(progressMode, cfg.LogLevel, os.Getenv)

			parentCtx := cmd.Context()
			if parentCtx == nil {
				parentCtx = context.Background()
			}
			ctx := parentCtx
			if cfg.ScanTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, cfg.ScanTimeout)
				defer cancel()
			}

			if allTags {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), repositorySweepWarning); err != nil {
					logger.Debug("progress update failed")
				}
			}

			progress := newProgressRendererWithMode(cmd.ErrOrStderr(), progressMode)
			startingMessage := "Preparing scan"
			if allTags {
				startingMessage = "Preparing repository sweep across every public tag"
			}
			if err := progress.Start(progressSnapshot{
				repository: ref.Repository,
				phase:      "Starting",
				message:    startingMessage,
			}); err != nil {
				logger.Debug("progress update failed")
			}
			// The explicit Finish call after publication reports errors; this is a safety net.
			defer func() { _ = progress.Finish() }()

			if noDatabase {
				openStore = func(config.Config) (storage.Store, error) { return storage.NewNoopStore(), nil }
			}
			store, err := openStore(cfg)
			if err != nil {
				if updateErr := progress.Update(progressSnapshot{
					repository: ref.Repository,
					phase:      "Error",
					message:    err.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
				return err
			}
			if closer, ok := store.(interface{ Close() error }); ok {
				defer func() {
					if err := closer.Close(); err != nil {
						logger.Debug("store close failed", "error", err)
					}
				}()
			}

			service := scanservice.New(cfg, store)
			outcome, err := service.ScanAndSave(ctx, scanservice.Request{
				Reference:      ref,
				Platform:       platform,
				AllTags:        allTags,
				ScannerVersion: effectiveVersion(),
				Logger:         logger,
				Progress: func(update jobs.ProgressUpdate) {
					if err := progress.UpdateFromJob(update); err != nil {
						logger.Debug("progress update failed", "error", err)
					}
				},
				BeforeSave: func(result jobs.Result) error {
					if store.Name() == "noop" {
						return nil
					}
					return progress.Update(progressSnapshot{
						repository:       ref.Repository,
						tagsCompleted:    result.TagsResolved,
						tagsFailed:       result.TagsFailed,
						tagsTotal:        result.TagsEnumerated,
						targetsCompleted: result.CompletedTargetCount,
						targetsFailed:    result.FailedTargetCount,
						targetsTotal:     result.TargetCount,
						findingsFound:    result.TotalFindings,
						phase:            "Saving Results",
						message:          "Persisting findings to Postgres",
					})
				},
			})
			result := outcome.Result
			scanErr := outcome.ScanError
			saveErr := outcome.SaveError
			operationErr := err
			if scanErr == nil && result.Status != jobs.ResultStatusCompleted {
				scanErr = &jobs.IncompleteError{
					Status:                 result.Status,
					CompletedManifestCount: result.CompletedManifestCount,
					FailedManifestCount:    result.FailedManifestCount,
				}
			}
			if operationErr == nil {
				operationErr = scanErr
			}
			// The scan error usually already wraps the context error; join
			// it only when it does not, so the cause is reported once.
			if ctx.Err() != nil && !errors.Is(operationErr, ctx.Err()) {
				operationErr = errors.Join(operationErr, ctx.Err())
			}
			acceptablePartial := canAcceptPartial(ctx, result, scanErr)
			acceptPartial := allowPartial && acceptablePartial
			// Cancellation and failures before a result existed are the only
			// silent paths. A failed scan still publishes its result (status
			// failed, diagnostics, per-target errors) on stdout and in the
			// local record so automation can see why it failed.
			if isCancellation(scanErr) || ctx.Err() != nil {
				if err := progress.Finish(); err != nil {
					logger.Debug("progress update failed")
				}
				return cancellationExit(parentCtx, ctx, cfg.ScanTimeout, operationErr)
			}
			if !hasPublishableResult(result) {
				if updateErr := progress.Update(progressSnapshot{
					repository: ref.Repository,
					phase:      "Error",
					message:    operationErr.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
				return operationErr
			}
			if scanErr != nil {
				if updateErr := progress.Update(progressSnapshot{
					repository:       ref.Repository,
					tagsCompleted:    result.TagsResolved,
					tagsFailed:       result.TagsFailed,
					tagsTotal:        result.TagsEnumerated,
					targetsCompleted: result.CompletedTargetCount,
					targetsPartial:   result.PartialTargetCount,
					targetsFailed:    result.FailedTargetCount,
					targetsTotal:     result.TargetCount,
					findingsFound:    result.TotalFindings,
					phase:            "Error",
					message:          scanErr.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
			}

			if err := progress.Update(progressSnapshot{
				repository:       ref.Repository,
				tagsCompleted:    result.TagsResolved,
				tagsFailed:       result.TagsFailed,
				tagsTotal:        result.TagsEnumerated,
				targetsCompleted: result.CompletedTargetCount,
				targetsFailed:    result.FailedTargetCount,
				targetsTotal:     result.TargetCount,
				findingsFound:    result.TotalFindings,
				phase:            "Saving Results",
				message:          "Writing scan record",
			}); err != nil {
				logger.Debug("progress update failed")
			}

			var artifact scanArtifact
			var publicationErr error
			if !noArtifacts {
				artifact, publicationErr = writeResultArtifacts(artifactOptions{outputDir: outputDir, configuredDir: cfg.FindingsDir}, outcome, store.Name())
			}
			if publicationErr != nil {
				if updateErr := progress.Update(progressSnapshot{
					repository:       ref.Repository,
					tagsCompleted:    result.TagsResolved,
					tagsFailed:       result.TagsFailed,
					tagsTotal:        result.TagsEnumerated,
					targetsCompleted: result.CompletedTargetCount,
					targetsPartial:   result.PartialTargetCount,
					targetsFailed:    result.FailedTargetCount,
					targetsTotal:     result.TargetCount,
					findingsFound:    result.TotalFindings,
					phase:            "Error",
					message:          publicationErr.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
			}
			if !cfg.PersistRawSecrets {
				findings.StripRawSecrets(result.DetailedFindings)
				findings.StripRawSecrets(result.SuppressedDetailedFindings)
			}

			if err := progress.Finish(); err != nil {
				logger.Debug("progress update failed")
			}
			for _, warning := range artifact.Warnings {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), warning); err != nil {
					logger.Debug("artifact warning reporting failed")
				}
			}
			if artifact.Path != "" {
				// The path is a trusted local value: %q keeps every byte
				// copyable instead of collapsing whitespace.
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Scan record: %q\n", artifact.Path); err != nil {
					logger.Debug("artifact path reporting failed")
				}
			}

			render := func(out io.Writer) error {
				switch outputFormat {
				case "json":
					encoder := json.NewEncoder(out)
					encoder.SetIndent("", "  ")
					return encoder.Encode(scanservice.PublicResult(result))
				case "summary":
					return renderSummary(out, result)
				default:
					return fmt.Errorf("unsupported output format: %s", outputFormat)
				}
			}
			if err := writeFormattedOutput(cmd.OutOrStdout(), outputPath, render); err != nil {
				return errors.Join(operationErr, publicationErr, err)
			}

			if publicationErr != nil || saveErr != nil {
				return errors.Join(operationErr, publicationErr)
			}
			warning, exit := exitForOutcome(result, scanErr, acceptablePartial, acceptPartial, failThreshold)
			if warning != "" {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), warning); err != nil {
					logger.Debug("progress update failed")
				}
			}
			return exit
		},
	}

	cmd.Flags().StringVar(&platform, "platform", "", "Scan only the specified platform as os, os/arch or os/arch/variant (default: every linux platform)")
	cmd.Flags().StringVar(&format, "format", "summary", "Output format: summary or json")
	cmd.Flags().BoolVar(&allTags, "all-tags", false, "Enumerate and scan every public tag in a bare repository reference")
	cmd.Flags().BoolVar(&allowPartial, "allow-partial", false, "Accept incomplete coverage when at least one manifest completed (otherwise exit code 3)")
	cmd.Flags().StringVar(&failOn, "fail-on", "low", "Lowest confidence of an actionable finding that produces exit code 2: low, medium, high, or none to report only")
	cmd.Flags().StringVar(&progressSetting, "progress", string(progressModeAuto), "Progress mode: auto, tty, plain, or off")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory for the scan record. Overrides LAYERLEAK_FINDINGS_DIR; the default is ./findings under the working directory.")
	cmd.Flags().StringVar(&outputPath, "output", "-", "Write the formatted result to this file instead of stdout; - means stdout.")
	cmd.Flags().BoolVar(&noArtifacts, "no-artifacts", false, "Do not write a scan record file.")
	cmd.Flags().BoolVar(&noDatabase, "no-db", false, "Do not open or write to PostgreSQL even when LAYERLEAK_DATABASE_URL is set.")
	cmd.Flags().IntVar(&tagPageSize, "tag-page-size", 0, "Registry tag-list page size for repository sweeps. Overrides LAYERLEAK_TAG_PAGE_SIZE. Must be greater than zero when set.")
	cmd.Flags().IntVar(&maxRepositoryTags, "max-repository-tags", 0, "Maximum tags enumerated per repository sweep. Overrides LAYERLEAK_MAX_REPOSITORY_TAGS. Set to 0 to disable the limit; negative values are rejected.")
	cmd.Flags().IntVar(&maxRepositoryTargets, "max-repository-targets", 0, "Maximum distinct targets resolved per repository sweep. Overrides LAYERLEAK_MAX_REPOSITORY_TARGETS. Set to 0 to disable the limit; negative values are rejected.")

	return cmd
}

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
	case "summary", "json":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported output format %q: use summary or json", value)
	}
}

func validateRepositoryScopeFlags(cmd *cobra.Command, allTags bool) error {
	if allTags {
		return nil
	}
	for _, name := range []string{"tag-page-size", "max-repository-tags", "max-repository-targets"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s requires --all-tags", name)
		}
	}
	return nil
}

func hasUsablePartialResult(result jobs.Result) bool {
	return result.ResultSchemaVersion > 0 && result.CompletedManifestCount > 0
}

// hasPublishableResult reports whether the scan produced a result at all. A
// failure before the scan started (registry client configuration, invalid
// request) leaves the zero Result, which is not worth printing or recording.
func hasPublishableResult(result jobs.Result) bool {
	return result.ResultSchemaVersion > 0
}

func canAcceptPartial(ctx context.Context, result jobs.Result, err error) bool {
	if err == nil || !hasUsablePartialResult(result) || scanservice.IsSaveError(err) || isCancellation(err) || manifest.IsIntegrityError(err) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	// A manifest whose layers are foreign or non-distributable is incomplete
	// coverage that --allow-partial may accept. It is typed separately from
	// integrity failures, which the check above keeps fail-closed.
	return jobs.IsIncomplete(err) || limits.IsExceeded(err) || scanner.IsUnsupportedManifest(err)
}

func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func applyScanScopeFlags(cmd *cobra.Command, cfg *config.Config, tagPageSize, maxRepositoryTags, maxRepositoryTargets int) error {
	if cmd.Flags().Changed("tag-page-size") {
		if tagPageSize <= 0 {
			return fmt.Errorf("--tag-page-size must be greater than zero")
		}
		cfg.TagPageSize = tagPageSize
	}
	if cmd.Flags().Changed("max-repository-tags") {
		if maxRepositoryTags < 0 {
			return fmt.Errorf("--max-repository-tags must be greater than or equal to zero")
		}
		cfg.MaxRepositoryTags = maxRepositoryTags
	}
	if cmd.Flags().Changed("max-repository-targets") {
		if maxRepositoryTargets < 0 {
			return fmt.Errorf("--max-repository-targets must be greater than or equal to zero")
		}
		cfg.MaxRepositoryTargets = maxRepositoryTargets
	}
	return nil
}

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
	return writer.Flush()
}

type summaryRow struct {
	label string
	value any
}

func summaryRows(result jobs.Result) []summaryRow {
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
		summaryRow{"Suppressed Example Findings", result.SuppressedFindingsCount},
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
