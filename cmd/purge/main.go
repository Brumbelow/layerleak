// Package main implements the Layerleak raw secret purge command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

const (
	// defaultPurgeTimeout bounds one run of the command. Each batch is also
	// bounded by LAYERLEAK_DATABASE_WRITE_TIMEOUT; this deadline covers the
	// whole walk. LAYERLEAK_PURGE_TIMEOUT=0 disables it.
	defaultPurgeTimeout = 30 * time.Minute
	purgeTimeoutEnv     = "LAYERLEAK_PURGE_TIMEOUT"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// options are the parsed command-line flags.
type options struct {
	confirm   bool
	dryRun    bool
	batchSize int
}

// parseOptions parses the flags. --dry-run never modifies the database and
// needs no --confirm; a real purge refuses to run without it.
func parseOptions(args []string, stderr io.Writer) (options, error) {
	flags := flag.NewFlagSet("layerleak-purge-raw-secrets", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var parsed options
	flags.BoolVar(&parsed.confirm, "confirm", false, "confirm irreversible deletion of stored raw secret material")
	flags.BoolVar(&parsed.dryRun, "dry-run", false, "report how many raw finding values and occurrence snippets would be purged, without changing anything")
	flags.IntVar(&parsed.batchSize, "batch-size", storage.DefaultPurgeBatchSize, "rows cleared per transaction; each batch briefly blocks concurrent scan writes")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("layerleak-purge-raw-secrets does not accept positional arguments")
	}
	if parsed.batchSize <= 0 {
		return options{}, fmt.Errorf("--batch-size must be greater than zero")
	}
	if !parsed.dryRun && !parsed.confirm {
		return options{}, fmt.Errorf("refusing to purge without --confirm; this operation irreversibly clears all stored raw secret values and snippets (use --dry-run to see the counts first)")
	}
	return parsed, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	parsed, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}
	timeout, err := durationFromEnv(purgeTimeoutEnv, defaultPurgeTimeout)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required")
	}
	store, err := storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL:       cfg.DatabaseURL,
		PersistRawSecrets: false,
		MaxOpenConns:      cfg.DatabaseMaxOpenConns,
		MaxIdleConns:      cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime:   cfg.DatabaseConnMaxLifetime,
		ConnMaxIdleTime:   cfg.DatabaseConnMaxIdleTime,
		QueryTimeout:      cfg.DatabaseQueryTimeout,
		WriteTimeout:      cfg.DatabaseWriteTimeout,
		RequireSchema:     true,
	})
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := purgeContext(ctx, timeout)
	defer cancel()

	if parsed.dryRun {
		counts, err := store.CountRawSecrets(ctx)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout,
			"dry run: %d raw finding value(s) and %d raw occurrence snippet(s) would be purged in batches of %d rows; nothing was changed\n",
			counts.FindingValues,
			counts.OccurrenceSnippets,
			parsed.batchSize,
		)
		return nil
	}

	counts, err := store.PurgeRawSecrets(ctx, storage.PurgeOptions{
		BatchSize: parsed.batchSize,
		Progress: func(progress storage.PurgeProgress) {
			_, _ = fmt.Fprintf(stderr,
				"cleared %d %s row(s); running total %d raw finding value(s), %d raw occurrence snippet(s)\n",
				progress.Rows,
				progress.Table,
				progress.Total.FindingValues,
				progress.Total.OccurrenceSnippets,
			)
		},
	})
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && timeout > 0 {
			return fmt.Errorf("%w (%s=%s elapsed after clearing %d finding value(s) and %d occurrence snippet(s); completed batches stay purged, rerun to continue)",
				err, purgeTimeoutEnv, timeout, counts.FindingValues, counts.OccurrenceSnippets)
		}
		return fmt.Errorf("%w (cleared %d finding value(s) and %d occurrence snippet(s) before stopping; completed batches stay purged)", err, counts.FindingValues, counts.OccurrenceSnippets)
	}
	_, _ = fmt.Fprintf(stdout,
		"purged %d raw finding value(s) and %d raw occurrence snippet(s)\n",
		counts.FindingValues,
		counts.OccurrenceSnippets,
	)
	return nil
}

// durationFromEnv reads a Go duration such as "30m" or "15s"; an unset or
// blank variable selects the fallback and negative values are rejected. The
// value is never echoed.
func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration such as 30m or 15s", name)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	return value, nil
}

// purgeContext bounds the run by the overall deadline; a zero timeout leaves
// only signal cancellation in place.
func purgeContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}
