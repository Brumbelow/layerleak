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
	"github.com/spf13/cobra"
)

const repositorySweepWarning = "warning: --all-tags enumerates every public tag in the repository and may scan many distinct images"

func newScanCmd() *cobra.Command {
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
					return err
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
				return err
			}
			defer progress.Finish()

			store, err := newStore(cfg)
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
			scanErr := err
			if scanErr == nil && result.Status != jobs.ResultStatusCompleted {
				scanErr = &jobs.IncompleteError{
					Status:                 result.Status,
					CompletedManifestCount: result.CompletedManifestCount,
					FailedManifestCount:    result.FailedManifestCount,
				}
			}
			acceptPartial := allowPartial && canAcceptPartial(ctx, result, scanErr)
			if scanErr != nil && (!hasUsablePartialResult(result) || scanservice.IsSaveError(scanErr) || isCancellation(scanErr)) {
				if updateErr := progress.Update(progressSnapshot{
					repository: ref.Repository,
					phase:      "Error",
					message:    scanErr.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
				return scanErr
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
				return err
			}

			resultPath, err := writeResultFile(cfg.FindingsDir, cfg.PersistRawSecrets, result)
			if err != nil {
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
					message:          err.Error(),
				}); updateErr != nil {
					logger.Debug("progress update failed", "error", updateErr)
				}
				return err
			}
			if !cfg.PersistRawSecrets {
				findings.StripRawSecrets(result.DetailedFindings)
				findings.StripRawSecrets(result.SuppressedDetailedFindings)
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
				phase:            "Saved",
				message:          savedResultMessage(resultPath),
			}); err != nil {
				return err
			}

			switch outputFormat {
			case "json":
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(result); err != nil {
					return err
				}
			case "summary":
				if err := renderSummary(cmd.OutOrStdout(), result); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported output format: %s", outputFormat)
			}

			if scanErr != nil && !acceptPartial {
				return exitError{code: 1, message: scanErr.Error()}
			}
			if acceptPartial {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "warning: incomplete scan accepted by --allow-partial"); err != nil {
					return err
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
	if _, err := fmt.Fprintf(writer, "Requested Reference:\t%s\n", sanitizeProgressValue(result.RequestedReference)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Repository:\t%s\n", sanitizeProgressValue(result.Repository)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Status:\t%s\n", result.Status); err != nil {
		return err
	}
	if result.ResolvedReference != "" {
		if _, err := fmt.Fprintf(writer, "Resolved Reference:\t%s\n", sanitizeProgressValue(result.ResolvedReference)); err != nil {
			return err
		}
	}
	if result.RequestedDigest != "" {
		if _, err := fmt.Fprintf(writer, "Requested Digest:\t%s\n", sanitizeProgressValue(result.RequestedDigest)); err != nil {
			return err
		}
	}
	if result.TagsEnumerated > 0 || result.Mode == "repository" {
		if _, err := fmt.Fprintf(writer, "Tags Enumerated:\t%d\n", result.TagsEnumerated); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "Tags Resolved:\t%d\n", result.TagsResolved); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "Tags Failed:\t%d\n", result.TagsFailed); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "Targets Selected:\t%d\n", result.TargetCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Targets Completed:\t%d\n", result.CompletedTargetCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Targets Partial:\t%d\n", result.PartialTargetCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Targets Failed:\t%d\n", result.FailedTargetCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Manifests Selected:\t%d\n", result.ManifestCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Manifests Completed:\t%d\n", result.CompletedManifestCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Manifests Failed:\t%d\n", result.FailedManifestCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Coverage Complete:\t%t\n", result.Coverage.Complete); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Files Scanned:\t%d\n", result.Coverage.FilesScanned); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Files Skipped Oversize:\t%d\n", result.Coverage.FilesSkippedOversize); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Total Findings:\t%d\n", result.TotalFindings); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Unique Fingerprints:\t%d\n", result.UniqueFingerprints); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Suppressed Example Findings:\t%d\n", result.SuppressedFindingsCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}
	if result.Mode == "reference" && len(result.Targets) == 1 {
		if _, err := fmt.Fprintln(writer, "Platform\tManifest Digest\tFindings\tStatus"); err != nil {
			return err
		}
		for _, item := range result.Targets[0].PlatformResults {
			status := "ok"
			if item.Error != "" {
				status = item.Error
			}
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", sanitizeProgressValue(item.Platform.String()), sanitizeProgressValue(item.ManifestDigest), item.FindingsCount, sanitizeProgressValue(status)); err != nil {
				return err
			}
		}
		return writer.Flush()
	}

	if _, err := fmt.Fprintln(writer, "Reference\tTags\tFindings\tStatus"); err != nil {
		return err
	}
	for _, item := range result.Targets {
		status := "ok"
		if item.Error != "" {
			status = item.Error
		}
		if _, err := fmt.Fprintf(writer, "%s\t%d\t%d\t%s\n", sanitizeProgressValue(targetReferenceLabel(item)), len(item.Tags), item.FindingsCount, sanitizeProgressValue(status)); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func targetReferenceLabel(item jobs.TargetResult) string {
	if item.ResolvedReference != "" {
		return item.ResolvedReference
	}
	return item.Reference
}
