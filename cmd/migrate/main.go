// Package main implements the Layerleak database migration command.
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
	"text/tabwriter"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
	"github.com/brumbelow/layerleak/v3/internal/version"
)

const (
	// defaultMigrationTimeout bounds the whole migrate run so a compose
	// `migrate` job cannot hang forever behind a lock or a stalled database.
	// Migration 0004 repairs and validates every row of populated tables, so
	// the default is generous; LAYERLEAK_MIGRATION_TIMEOUT=0 disables it.
	defaultMigrationTimeout = 30 * time.Minute
	migrationTimeoutEnv     = "LAYERLEAK_MIGRATION_TIMEOUT"
	migrationLockTimeoutEnv = "LAYERLEAK_MIGRATION_LOCK_TIMEOUT"
)

// Exit statuses. --status uses exitPending to say "migrations are waiting"
// without it being an error.
const (
	exitOK      = 0
	exitError   = 1
	exitPending = 2
)

var errUsage = errors.New("usage")

func main() {
	code, err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

// mode is the one action a run performs.
type mode int

const (
	modeApply mode = iota
	modeStatus
	modeDryRun
	modeVersion
)

// parseMode parses the flags. Exactly one of --status, --dry-run and
// --version may be given; none means apply.
func parseMode(args []string, stderr io.Writer) (mode, error) {
	flags := flag.NewFlagSet("layerleak-migrate-up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	status := flags.Bool("status", false, "print the migration ledger against the shipped files and exit 0 when current, 2 when migrations are pending")
	dryRun := flags.Bool("dry-run", false, "list the migrations that would be applied without applying them")
	showVersion := flags.Bool("version", false, "print the build version and exit")
	if err := flags.Parse(args); err != nil {
		return modeApply, err
	}
	if flags.NArg() != 0 {
		return modeApply, fmt.Errorf("%w: layerleak-migrate-up does not accept positional arguments", errUsage)
	}
	selected := 0
	chosen := modeApply
	for _, candidate := range []struct {
		set  bool
		mode mode
	}{{*status, modeStatus}, {*dryRun, modeDryRun}, {*showVersion, modeVersion}} {
		if candidate.set {
			selected++
			chosen = candidate.mode
		}
	}
	if selected > 1 {
		return modeApply, fmt.Errorf("%w: --status, --dry-run and --version are mutually exclusive", errUsage)
	}
	return chosen, nil
}

func run(args []string, stdout, stderr io.Writer) (int, error) {
	selected, err := parseMode(args, stderr)
	if err != nil {
		return exitError, err
	}
	if selected == modeVersion {
		_, _ = fmt.Fprintf(stdout, "layerleak-migrate-up %s\n", version.Effective())
		return exitOK, nil
	}

	databaseURL := strings.TrimSpace(os.Getenv("LAYERLEAK_DATABASE_URL"))
	if databaseURL == "" {
		return exitError, fmt.Errorf("LAYERLEAK_DATABASE_URL is required")
	}
	migrationsDir := strings.TrimSpace(os.Getenv("LAYERLEAK_MIGRATIONS_DIR"))
	if migrationsDir == "" {
		migrationsDir = "/app/migrations"
	}
	timeout, err := durationFromEnv(migrationTimeoutEnv, defaultMigrationTimeout)
	if err != nil {
		return exitError, err
	}
	lockTimeout, err := durationFromEnv(migrationLockTimeoutEnv, storage.DefaultMigrationLockTimeout)
	if err != nil {
		return exitError, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := migrationContext(ctx, timeout)
	defer cancel()

	config := storage.MigrationConfig{
		DatabaseURL: databaseURL,
		Directory:   migrationsDir,
		LockTimeout: lockTimeout,
		Progress: func(message string) {
			_, _ = fmt.Fprintln(stderr, message)
		},
	}

	switch selected {
	case modeStatus, modeDryRun:
		status, err := storage.MigrationStatus(ctx, config)
		if err != nil {
			return exitError, timeoutHint(ctx, err, timeout)
		}
		if selected == modeDryRun {
			renderDryRun(stdout, status)
			return exitOK, nil
		}
		renderStatus(stdout, status)
		return statusExitCode(status), nil
	default:
	}

	result, err := storage.RunMigrations(ctx, config)
	if err != nil {
		return exitError, timeoutHint(ctx, err, timeout)
	}
	for _, name := range result.Applied {
		_, _ = fmt.Fprintf(stdout, "applied %s\n", name)
	}
	_, _ = fmt.Fprintf(stdout, "database schema is up to date at %s\n", result.Current)
	return exitOK, nil
}

// timeoutHint explains a failure that coincided with the run deadline.
func timeoutHint(ctx context.Context, err error, timeout time.Duration) error {
	if ctx.Err() != nil && timeout > 0 {
		return fmt.Errorf("%w (%s=%s elapsed; a migration may still be waiting on a lock held by another session)", err, migrationTimeoutEnv, timeout)
	}
	return err
}

// statusExitCode maps a status to the documented exit code.
func statusExitCode(status storage.MigrationStatusResult) int {
	if status.UpToDate() {
		return exitOK
	}
	return exitPending
}

// renderStatus prints the ledger comparison as a table followed by a summary.
func renderStatus(out io.Writer, status storage.MigrationStatusResult) {
	ledgerState := "present"
	if !status.LedgerExists {
		ledgerState = "absent"
	}
	_, _ = fmt.Fprintf(out, "ledger: %s (%s)\n", status.Ledger, ledgerState)
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "VERSION\tNAME\tSTATE\tAPPLIED AT\tSHA256")
	for _, entry := range status.Entries {
		state, appliedAt := "pending", "-"
		switch {
		case entry.Applied:
			state = "applied"
			appliedAt = entry.AppliedAt.UTC().Format(time.RFC3339)
		case entry.Adoptable:
			state = "adoptable"
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", entry.Version, entry.Name, state, appliedAt, entry.Checksum)
	}
	_ = table.Flush()
	current := status.Current
	if current == "" {
		current = "none"
	}
	_, _ = fmt.Fprintf(out, "current: %s  expected: %s  pending: %d  adoptable: %d\n", current, status.Expected, len(status.Pending), len(status.Adoptable))
	if status.UpToDate() {
		_, _ = fmt.Fprintf(out, "database schema is up to date at %s\n", status.Expected)
	} else {
		_, _ = fmt.Fprintln(out, "migrations are pending; run layerleak-migrate-up to apply them")
	}
}

// renderDryRun lists what RunMigrations would do.
func renderDryRun(out io.Writer, status storage.MigrationStatusResult) {
	for _, name := range status.Adoptable {
		_, _ = fmt.Fprintf(out, "would adopt %s (legacy schema already matches; the ledger row would be recorded without running the file)\n", name)
	}
	for _, name := range status.Pending {
		_, _ = fmt.Fprintf(out, "would apply %s\n", name)
	}
	if status.UpToDate() {
		_, _ = fmt.Fprintf(out, "database schema is up to date at %s; nothing to apply\n", status.Expected)
		return
	}
	current := status.Current
	if current == "" {
		current = "none"
	}
	_, _ = fmt.Fprintf(out, "dry run: database schema would move from %s to %s; nothing was changed\n", current, status.Expected)
}

// durationFromEnv reads a Go duration such as "30m" or "15s"; an unset or
// blank variable selects the fallback and negative values are rejected.
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

// migrationContext bounds the run by the overall deadline; a zero timeout
// leaves only signal cancellation in place.
func migrationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}
