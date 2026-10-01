package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
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

// innerDeadlineHint follows a scan error whose deadline was a per-request or
// per-blob one, so the operator is pointed at the setting that actually fired.
const innerDeadlineHint = " (a per-blob or per-request deadline expired; see LAYERLEAK_BLOB_TIMEOUT and LAYERLEAK_HTTP_TIMEOUT)"

// cancellationExit builds the single, descriptive error for a run that ended
// because a context ended. A signal names itself; the scan deadline names
// LAYERLEAK_SCAN_TIMEOUT only when ctx (the scan-timeout context derived from
// parent) itself expired; a deadline that expired deeper in the scan (the
// per-blob LAYERLEAK_BLOB_TIMEOUT or per-request LAYERLEAK_HTTP_TIMEOUT
// contexts) keeps the scan error text and hints at those settings; any other
// cancellation is reported once. cause stays wrapped so
// errors.Is(err, context.Canceled) and similar keep working.
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
	case ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		message = fmt.Sprintf("scan exceeded LAYERLEAK_SCAN_TIMEOUT (%s)", timeout)
	case cause != nil && errors.Is(cause, context.DeadlineExceeded):
		message = cause.Error() + innerDeadlineHint
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
// reports whether it did. registryHost names the registry in the message
// for an authentication failure. The returned warning is printed when
// coverage was accepted.
func exitForOutcome(result jobs.Result, scanErr error, acceptable, accepted bool, threshold failOnLevel, registryHost string) (string, error) {
	blocking := countBlockingFindings(result.Findings, threshold)
	switch {
	case scanErr != nil && !acceptable:
		return "", exitError{code: exitCodeFailure, message: scanFailureMessage(scanErr, registryHost), cause: scanErr}
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

// scanFailureMessage is the operator-facing text for a failed scan. A 401 or
// 403 from the registry (or its token endpoint) becomes a plain
// authentication failure that names the host and never echoes the request.
func scanFailureMessage(scanErr error, registryHost string) string {
	if registry.IsUnauthorized(scanErr) {
		return fmt.Sprintf("authentication to %s failed", registryHost)
	}
	return scanErr.Error()
}

// registryHostFor names the host a scan contacts: the LAYERLEAK_REGISTRY_BASE_URL
// override when set, otherwise the reference's registry.
func registryHostFor(cfg config.Config, ref manifest.Reference) string {
	if cfg.RegistryBaseURL != "" {
		if parsed, err := url.Parse(cfg.RegistryBaseURL); err == nil && parsed.Host != "" {
			return parsed.Host
		}
		return cfg.RegistryBaseURL
	}
	return ref.Registry
}

// maxPasswordBytes bounds the stdin read for --password-stdin.
const maxPasswordBytes = 64 * 1024

// readPasswordStdin reads the whole of stdin and removes exactly one trailing
// newline (LF or CRLF), so a password piped with echo or from a file works
// while a password that legitimately ends in a newline character is still
// representable by adding a second one.
func readPasswordStdin(stdin io.Reader) (string, error) {
	if stdin == nil {
		return "", errors.New("--password-stdin: no standard input")
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxPasswordBytes+1))
	if err != nil {
		return "", fmt.Errorf("--password-stdin: read standard input: %w", err)
	}
	if len(data) > maxPasswordBytes {
		return "", fmt.Errorf("--password-stdin: password exceeds %d bytes", maxPasswordBytes)
	}
	password := string(data)
	if strings.HasSuffix(password, "\n") {
		password = strings.TrimSuffix(password, "\n")
		password = strings.TrimSuffix(password, "\r")
	}
	if password == "" {
		return "", errors.New("--password-stdin: standard input is empty")
	}
	return password, nil
}

// credentialFromFlags validates the --username/--password-stdin pair (both or
// neither) and reads the password. The zero credential means "not given".
func credentialFromFlags(username string, passwordStdin bool, stdin io.Reader) (registry.Credential, error) {
	username = strings.TrimSpace(username)
	switch {
	case username == "" && !passwordStdin:
		return registry.Credential{}, nil
	case username == "":
		return registry.Credential{}, errors.New("--password-stdin requires --username")
	case !passwordStdin:
		return registry.Credential{}, errors.New("--username requires --password-stdin (a --password flag is deliberately not offered: it would expose the secret in process listings and shell history)")
	}
	password, err := readPasswordStdin(stdin)
	if err != nil {
		return registry.Credential{}, err
	}
	return registry.Credential{Username: username, Password: password}, nil
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
