package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var platform string
	var format string

	cmd := &cobra.Command{
		Use:   "scan <image-ref>",
		Short: "Scan a public OCI image reference from any supported registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger, err := newLogger(cfg.LogLevel)
			if err != nil {
				return err
			}

			ref, err := manifest.ParseReference(args[0])
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			progress := newProgressRenderer(cmd.ErrOrStderr())
			if err := progress.Start(progressSnapshot{
				repository: ref.Repository,
				phase:      "Starting",
				message:    "Preparing scan",
			}); err != nil {
				return err
			}
			defer progress.Finish()

			store, err := newStore(cfg)
			if err != nil {
				_ = progress.Update(progressSnapshot{
					repository: ref.Repository,
					phase:      "Error",
					message:    err.Error(),
				})
				return err
			}
			if closer, ok := store.(interface{ Close() error }); ok {
				defer closer.Close()
			}

			service := scanservice.New(cfg, store)
			outcome, err := service.ScanAndSave(ctx, scanservice.Request{
				Reference: ref,
				Platform:  platform,
				Logger:    logger,
				Progress: func(update jobs.ProgressUpdate) {
					_ = progress.UpdateFromJob(update)
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
			limitExceeded := limits.IsExceeded(scanErr)
			if scanErr != nil && !limitExceeded {
				_ = progress.Update(progressSnapshot{
					repository: ref.Repository,
					phase:      "Error",
					message:    scanErr.Error(),
				})
				return scanErr
			}
			if scanErr != nil {
				_ = progress.Update(progressSnapshot{
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
				})
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
				_ = progress.Update(progressSnapshot{
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
				})
				return err
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

			switch format {
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
				return fmt.Errorf("unsupported output format: %s", format)
			}

			if scanErr != nil {
				return exitError{code: 1, message: scanErr.Error()}
			}
			if result.TotalFindings > 0 {
				return exitError{code: 2}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&platform, "platform", "", "Scan only the specified platform in os/arch[/variant] format")
	cmd.Flags().StringVar(&format, "format", "summary", "Output format: summary or json")

	return cmd
}

func renderSummary(output io.Writer, result jobs.Result) error {
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "Requested Reference:\t%s\n", result.RequestedReference); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Repository:\t%s\n", result.Repository); err != nil {
		return err
	}
	if result.ResolvedReference != "" {
		if _, err := fmt.Fprintf(writer, "Resolved Reference:\t%s\n", result.ResolvedReference); err != nil {
			return err
		}
	}
	if result.RequestedDigest != "" {
		if _, err := fmt.Fprintf(writer, "Requested Digest:\t%s\n", result.RequestedDigest); err != nil {
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
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", item.Platform.String(), item.ManifestDigest, item.FindingsCount, status); err != nil {
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
		if _, err := fmt.Fprintf(writer, "%s\t%d\t%d\t%s\n", targetReferenceLabel(item), len(item.Tags), item.FindingsCount, status); err != nil {
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
