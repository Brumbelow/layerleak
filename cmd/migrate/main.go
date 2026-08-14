// Package main implements the Layerleak database migration command.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/brumbelow/layerleak/internal/storage"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := storage.RunMigrations(ctx, storage.MigrationConfig{
		DatabaseURL: databaseURL,
		Directory:   migrationsDir,
	})
	if err != nil {
		return err
	}
	for _, name := range result.Applied {
		fmt.Printf("applied %s\n", name)
	}
	fmt.Printf("database schema is up to date at %s\n", result.Current)
	return nil
}
