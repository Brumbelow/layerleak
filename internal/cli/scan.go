package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
	"github.com/spf13/cobra"
)

const repositorySweepWarning = "warning: --all-tags enumerates every public tag in the repository and may scan many distinct images"

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
			logger, err := newLogger(cfg.LogLevel)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
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
			defer progress.Finish()

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
				defer closer.Close()
			}

			service := scanservice.New(cfg, store)
			outcome, err := service.ScanAndSave(ctx, scanservice.Request{
				Reference: ref,
				Platform:  platform,
				AllTags:   allTags,
				Logger:    logger,
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
			if ctx.Err() != nil {
				operationErr = errors.Join(operationErr, ctx.Err())
			}
			acceptPartial := allowPartial && canAcceptPartial(ctx, result, scanErr)
			if isCancellation(scanErr) || ctx.Err() != nil || (scanErr != nil && !hasUsablePartialResult(result)) {
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
				message:          "Writing findings file",
			}); err != nil {
				logger.Debug("progress update failed")
			}

			artifactPaths, publicationErr := writeResultArtifacts(cfg.FindingsDir, cfg.PersistRawSecrets, outcome, store.Name())
			if publicationErr != nil {
				if updateErr := progress.Update(progressSnapshot{
					repository:       ref.Repository,
					tagsCompleted:    result.TagsResolved,
					tagsFailed:       result.TagsFailed,
					tagsTotal:        result.TagsEnumerated,
					targetsCompleted: result.CompletedTargetCount,
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
			for _, artifact := range []struct{ label, path string }{
				{"Findings", artifactPaths.Findings}, {"Scan record", artifactPaths.Scan},
			} {
				if artifact.path == "" {
					continue
				}
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", artifact.label, sanitizeProgressValue(artifact.path)); err != nil {
					logger.Debug("artifact path reporting failed")
				}
			}

			switch outputFormat {
			case "json":
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(scanservice.RedactedResult(result)); err != nil {
					return errors.Join(operationErr, publicationErr, err)
				}
			case "summary":
				if err := renderSummary(cmd.OutOrStdout(), result); err != nil {
					return errors.Join(operationErr, publicationErr, err)
				}
			default:
				return fmt.Errorf("unsupported output format: %s", outputFormat)
			}

			if publicationErr != nil || saveErr != nil {
				return errors.Join(operationErr, publicationErr)
			}
			if scanErr != nil && !acceptPartial {
				return exitError{code: 1, message: scanErr.Error()}
			}
			if acceptPartial {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "warning: incomplete scan accepted by --allow-partial"); err != nil {
					logger.Debug("progress update failed")
				}
			}
			if result.TotalFindings > 0 {
				return exitError{code: 2}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&platform, "platform", "", "Scan only the specified platform in os/arch[/variant] format")
	cmd.Flags().StringVar(&format, "format", "summary", "Output format: summary or json")
	cmd.Flags().BoolVar(&allTags, "all-tags", false, "Enumerate and scan every public tag in a bare repository reference")
	cmd.Flags().BoolVar(&allowPartial, "allow-partial", false, "Accept incomplete coverage when at least one manifest completed")
	cmd.Flags().StringVar(&progressSetting, "progress", string(progressModeAuto), "Progress mode: auto, tty, plain, or off")
	cmd.Flags().IntVar(&tagPageSize, "tag-page-size", 0, "Registry tag-list page size for repository sweeps. Overrides LAYERLEAK_TAG_PAGE_SIZE. Must be greater than zero when set.")
	cmd.Flags().IntVar(&maxRepositoryTags, "max-repository-tags", 0, "Maximum tags enumerated per repository sweep. Overrides LAYERLEAK_MAX_REPOSITORY_TAGS. Set to 0 to disable the limit; negative values are rejected.")
	cmd.Flags().IntVar(&maxRepositoryTargets, "max-repository-targets", 0, "Maximum distinct targets resolved per repository sweep. Overrides LAYERLEAK_MAX_REPOSITORY_TARGETS. Set to 0 to disable the limit; negative values are rejected.")

	return cmd
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

func canAcceptPartial(ctx context.Context, result jobs.Result, err error) bool {
	if err == nil || !hasUsablePartialResult(result) || scanservice.IsSaveError(err) || isCancellation(err) || manifest.IsIntegrityError(err) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return jobs.IsIncomplete(err) || limits.IsExceeded(err)
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
