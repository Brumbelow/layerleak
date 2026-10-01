// Package main implements the Layerleak database migration command.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 1 {
		return fmt.Errorf("layerleak-migrate-up does not accept arguments")
	}
	databaseURL := strings.TrimSpace(os.Getenv("LAYERLEAK_DATABASE_URL"))
	if databaseURL == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required")
	}
	migrationsDir := strings.TrimSpace(os.Getenv("LAYERLEAK_MIGRATIONS_DIR"))
	if migrationsDir == "" {
		migrationsDir = "/app/migrations"
	}
	timeout, err := durationFromEnv(migrationTimeoutEnv, defaultMigrationTimeout)
	if err != nil {
		return err
	}
	lockTimeout, err := durationFromEnv(migrationLockTimeoutEnv, storage.DefaultMigrationLockTimeout)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := migrationContext(ctx, timeout)
	defer cancel()

	result, err := storage.RunMigrations(ctx, storage.MigrationConfig{
		DatabaseURL: databaseURL,
		Directory:   migrationsDir,
		LockTimeout: lockTimeout,
		Progress: func(message string) {
			fmt.Fprintln(os.Stderr, message)
		},
	})
	if err != nil {
		if ctx.Err() != nil && timeout > 0 {
			return fmt.Errorf("%w (%s=%s elapsed; a migration may still be waiting on a lock held by another session)", err, migrationTimeoutEnv, timeout)
		}
		return err
	}
	for _, name := range result.Applied {
		fmt.Printf("applied %s\n", name)
	}
	fmt.Printf("database schema is up to date at %s\n", result.Current)
	return nil
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
