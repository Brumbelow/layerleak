package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/tabwriter"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/config"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/detectors"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/registry"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var platform string
	var format string

	cmd := &cobra.Command{
		Use:   "scan <image-ref>",
		Short: "Scan a public Docker Hub image reference",
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

			registryClient := registry.NewClient(registry.Options{
				BaseURL: cfg.RegistryBaseURL,
				AuthURL: cfg.RegistryAuthURL,
				HTTPClient: &http.Client{
					Timeout: cfg.HTTPTimeout,
				},
			})
			detectorSet := detectors.Default()

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			progress := newProgressRenderer(cmd.ErrOrStderr())
			if err := progress.Start(progressSnapshot{
				repository:        ref.Repository,
				repositoriesTotal: 1,
				phase:             "Starting",
				message:           "Preparing scan",
			}); err != nil {
				return err
			}
			defer progress.Finish()

			result, err := scanner.Scan(ctx, scanner.Request{
				Reference:    ref,
				Platform:     platform,
				Registry:     registryClient,
				Detectors:    detectorSet,
				Logger:       logger,
				MaxFileBytes: cfg.MaxFileBytes,
				Progress: func(update scanner.ProgressUpdate) {
					_ = progress.UpdateFromScan(update)
				},
			})
			if err != nil {
				_ = progress.Update(progressSnapshot{
					repository:            ref.Repository,
					repositoriesTotal:     1,
					repositoriesCompleted: 1,
					phase:                 "Error",
					message:               err.Error(),
				})
				return err
			}

			if err := progress.Update(progressSnapshot{
				repository:            ref.Repository,
				repositoriesTotal:     1,
				repositoriesCompleted: 1,
				manifestCompleted:     result.CompletedManifestCount,
				manifestFailed:        result.FailedManifestCount,
				manifestTotal:         result.ManifestCount,
				findingsFound:         result.TotalFindings,
				phase:                 "Saving Results",
				message:               "Writing findings file",
			}); err != nil {
				return err
			}

			resultPath, err := writeResultFile(cfg.FindingsDir, result)
			if err != nil {
				_ = progress.Update(progressSnapshot{
					repository:            ref.Repository,
					repositoriesTotal:     1,
					repositoriesCompleted: 1,
					manifestCompleted:     result.CompletedManifestCount,
					manifestFailed:        result.FailedManifestCount,
					manifestTotal:         result.ManifestCount,
					findingsFound:         result.TotalFindings,
					phase:                 "Error",
					message:               err.Error(),
				})
				return err
			}

			if err := progress.Update(progressSnapshot{
				repository:            ref.Repository,
				repositoriesTotal:     1,
				repositoriesCompleted: 1,
				manifestCompleted:     result.CompletedManifestCount,
				manifestFailed:        result.FailedManifestCount,
				manifestTotal:         result.ManifestCount,
				findingsFound:         result.TotalFindings,
				phase:                 "Saved",
				message:               savedResultMessage(resultPath),
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

func renderSummary(output io.Writer, result scanner.Result) error {
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "Requested Reference:\t%s\n", result.RequestedReference); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Resolved Reference:\t%s\n", result.ResolvedReference); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Requested Digest:\t%s\n", result.RequestedDigest); err != nil {
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
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Platform\tManifest Digest\tFindings\tStatus"); err != nil {
		return err
	}
	for _, item := range result.PlatformResults {
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
