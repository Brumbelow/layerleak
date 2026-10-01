package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

func TestNewDefaultLoggerHonorsConfiguredLevel(t *testing.T) {
	logger, err := newDefaultLogger("warn", "json")
	if err != nil {
		t.Fatalf("newDefaultLogger() error = %v", err)
	}
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info logging is enabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("warn logging is disabled at warn level")
	}
	if _, err := newDefaultLogger("verbose", "json"); err == nil {
		t.Fatal("newDefaultLogger(verbose) error = nil")
	}
}

// TestNewDefaultLoggerSelectsHandlerByFormat pins the API to the shared
// internal/logging constructor: LAYERLEAK_LOG_FORMAT=text yields a text
// handler, json a JSON handler, and anything else is rejected.
func TestNewDefaultLoggerSelectsHandlerByFormat(t *testing.T) {
	jsonLogger, err := newDefaultLogger("info", "json")
	if err != nil {
		t.Fatalf("newDefaultLogger(json) error = %v", err)
	}
	if _, ok := jsonLogger.Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("json handler = %T", jsonLogger.Handler())
	}
	textLogger, err := newDefaultLogger("info", "text")
	if err != nil {
		t.Fatalf("newDefaultLogger(text) error = %v", err)
	}
	if _, ok := textLogger.Handler().(*slog.TextHandler); !ok {
		t.Fatalf("text handler = %T", textLogger.Handler())
	}
	if _, err := newDefaultLogger("info", "yaml"); err == nil || !strings.Contains(err.Error(), "unsupported log format") {
		t.Fatalf("newDefaultLogger(yaml) error = %v", err)
	}
}

// recordingRawSecretCounter captures the deadline the startup inventory runs
// under.
type recordingRawSecretCounter struct {
	deadline time.Time
	hasLimit bool
	counts   storage.RawSecretCounts
	err      error
}

func (c *recordingRawSecretCounter) CountRawSecrets(ctx context.Context) (storage.RawSecretCounts, error) {
	c.deadline, c.hasLimit = ctx.Deadline()
	return c.counts, c.err
}

// TestWarnAboutRawSecretsUsesQueryTimeout pins API-21: the startup inventory
// runs under the database query timeout, not the 2 s readiness probe budget.
func TestWarnAboutRawSecretsUsesQueryTimeout(t *testing.T) {
	counter := &recordingRawSecretCounter{counts: storage.RawSecretCounts{FindingValues: 3, OccurrenceSnippets: 5}}
	logs := &bytes.Buffer{}
	before := time.Now()

	warnAboutRawSecrets(counter, 10*time.Second, testLogger(logs))

	if !counter.hasLimit {
		t.Fatal("inventory ran without a deadline")
	}
	if remaining := counter.deadline.Sub(before); remaining < 9*time.Second || remaining > 11*time.Second {
		t.Fatalf("deadline %s from start, want about 10s", remaining)
	}
	if !strings.Contains(logs.String(), `"finding_values":3`) || !strings.Contains(logs.String(), `"occurrence_snippets":5`) || !strings.Contains(logs.String(), "layerleak-purge-raw-secrets") {
		t.Fatalf("warning = %s", logs.String())
	}
}

func TestWarnAboutRawSecretsStaysQuietWhenClean(t *testing.T) {
	logs := &bytes.Buffer{}
	warnAboutRawSecrets(&recordingRawSecretCounter{}, time.Second, testLogger(logs))
	if logs.Len() != 0 {
		t.Fatalf("unexpected log: %s", logs.String())
	}
}

func TestWarnAboutRawSecretsReportsFailureByType(t *testing.T) {
	logs := &bytes.Buffer{}
	warnAboutRawSecrets(&recordingRawSecretCounter{err: errors.New("synthetic dsn detail")}, time.Second, testLogger(logs))
	if !strings.Contains(logs.String(), "could not inspect historical raw secret storage") || strings.Contains(logs.String(), "synthetic dsn detail") {
		t.Fatalf("warning = %s", logs.String())
	}
}
