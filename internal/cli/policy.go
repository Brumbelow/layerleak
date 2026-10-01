package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
)

// failOnLevel is the --fail-on threshold: the lowest confidence of an
// actionable finding that produces exit code 2.
type failOnLevel int

const (
	failOnLow failOnLevel = iota
	failOnMedium
	failOnHigh
	// failOnNone reports findings without failing the exit status.
	failOnNone
)

const allowPartialHint = " (re-run with --allow-partial to accept usable partial coverage)"

func parseFailOn(value string) (failOnLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return failOnLow, nil
	case "medium":
		return failOnMedium, nil
	case "high":
		return failOnHigh, nil
	case "none":
		return failOnNone, nil
	default:
		return 0, fmt.Errorf("unsupported --fail-on value %q: use low, medium, high, or none", value)
	}
}

// confidenceRank orders detector confidence; unknown values count as low so a
// detector with a missing confidence can never slip under the threshold.
func confidenceRank(confidence string) failOnLevel {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return failOnHigh
	case "medium":
		return failOnMedium
	default:
		return failOnLow
	}
}

// countBlockingFindings counts the actionable findings at or above the
// threshold. Suppressed findings are never in items and never block.
func countBlockingFindings(items []findings.Finding, threshold failOnLevel) int {
	if threshold == failOnNone {
		return 0
	}
	count := 0
	for _, item := range items {
		if confidenceRank(item.Confidence) >= threshold {
			count++
		}
	}
	return count
}

// cancellationExit builds the single, descriptive error for a run that ended
// because its context ended: the scan deadline names LAYERLEAK_SCAN_TIMEOUT,
// a signal names itself, and any other cancellation is reported once. cause
// stays wrapped so errors.Is(err, context.Canceled) and similar keep working.
func cancellationExit(parent, ctx context.Context, timeout time.Duration, cause error) exitError {
	message := "scan canceled"
	switch {
	case parent != nil && parent.Err() != nil:
		var bySignal *signalCancellation
		if errors.As(context.Cause(parent), &bySignal) {
			message = bySignal.Error()
		} else {
			message = "scan canceled by the caller"
		}
	case (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) || errors.Is(cause, context.DeadlineExceeded):
		message = fmt.Sprintf("scan exceeded LAYERLEAK_SCAN_TIMEOUT (%s)", timeout)
	}
	return exitError{code: exitCodeFailure, message: message, cause: cause}
}

// exitForOutcome maps a published scan outcome to the exit contract:
//
//	1  the scan failed, or its error is one --allow-partial cannot accept
//	2  actionable findings at or above --fail-on (they take precedence over 3)
//	3  usable but incomplete coverage that --allow-partial did not accept
//	0  otherwise
//
// acceptable reports whether --allow-partial could accept scanErr; accepted
// reports whether it did. The returned warning is printed when coverage was
// accepted.
func exitForOutcome(result jobs.Result, scanErr error, acceptable, accepted bool, threshold failOnLevel) (string, error) {
	blocking := countBlockingFindings(result.Findings, threshold)
	switch {
	case scanErr != nil && !acceptable:
		return "", exitError{code: exitCodeFailure, message: scanErr.Error(), cause: scanErr}
	case scanErr != nil && !accepted:
		message := scanErr.Error() + allowPartialHint
		if blocking > 0 {
			return "", exitError{code: exitCodeFindings, message: message, cause: scanErr}
		}
		return "", exitError{code: exitCodeIncomplete, message: message, cause: scanErr}
	}
	warning := ""
	if accepted {
		warning = "warning: incomplete scan accepted by --allow-partial"
	}
	if blocking > 0 {
		return warning, exitError{code: exitCodeFindings}
	}
	return warning, nil
}

// effectiveProgressMode resolves "auto": the dynamic terminal block is not
// used when debug logging would interleave with it, or when the terminal is
// declared dumb or the run is a CI job (TERM=dumb, CI=true).
func effectiveProgressMode(mode progressMode, logLevel string, lookup func(string) string) progressMode {
	if mode != progressModeAuto {
		return mode
	}
	if level, err := parseLogLevel(logLevel); err == nil && level <= slog.LevelDebug {
		return progressModePlain
	}
	if strings.EqualFold(strings.TrimSpace(lookup("TERM")), "dumb") {
		return progressModePlain
	}
	switch strings.ToLower(strings.TrimSpace(lookup("CI"))) {
	case "true", "1", "yes":
		return progressModePlain
	}
	return mode
}
