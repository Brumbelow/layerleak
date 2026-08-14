// Package main implements the Layerleak raw secret purge command.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("layerleak-purge-raw-secrets", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	confirmed := flags.Bool("confirm", false, "confirm irreversible deletion of stored raw secret material")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("layerleak-purge-raw-secrets does not accept positional arguments")
	}
	if !*confirmed {
		return fmt.Errorf("refusing to purge without --confirm; this operation irreversibly clears all stored raw secret values and snippets")
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
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	counts, err := store.PurgeRawSecrets(ctx)
	if err != nil {
		return err
	}
	fmt.Printf(
		"purged %d raw finding value(s) and %d raw occurrence snippet(s)\n",
		counts.FindingValues,
		counts.OccurrenceSnippets,
	)
	return nil
}
