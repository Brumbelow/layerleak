package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := newDefaultLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required for the API")
	}

	store, err := storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL:       cfg.DatabaseURL,
		PersistRawSecrets: cfg.PersistRawSecrets,
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
	if !cfg.PersistRawSecrets {
		warningCtx, cancel := context.WithTimeout(context.Background(), cfg.APIReadinessTimeout)
		counts, countErr := store.CountRawSecrets(warningCtx)
		cancel()
		if countErr != nil {
			slog.Warn("could not inspect historical raw secret storage", "error_type", fmt.Sprintf("%T", countErr))
		} else if counts.Total() > 0 {
			slog.Warn(
				"database still contains raw secret material from an earlier opt-in; run layerleak-purge-raw-secrets --confirm to remove it",
				"finding_values", counts.FindingValues,
				"occurrence_snippets", counts.OccurrenceSnippets,
			)
		}
	}

	server := &http.Server{
		Addr: cfg.APIAddr,
		Handler: NewHandlerWithOptions(scanservice.New(cfg, store), store, HandlerOptions{
			MaxRequestBytes:    cfg.APIMaxRequestBytes,
			ScanTimeout:        cfg.APIScanTimeout,
			MaxConcurrentScans: cfg.APIMaxConcurrentScans,
			QueryTimeout:       cfg.DatabaseQueryTimeout,
			ReadinessTimeout:   cfg.APIReadinessTimeout,
			ResponseTimeout:    cfg.APIResponseWriteTimeout,
		}),
		ReadHeaderTimeout: cfg.APIReadHeaderTimeout,
		ReadTimeout:       cfg.APIReadTimeout,
		IdleTimeout:       cfg.APIIdleTimeout,
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		return err
	case <-signalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.APIShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown api server: %w", err)
		}
		if err := <-serverErr; err != nil {
			return err
		}
		return nil
	}
}

func newDefaultLogger(levelName string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(levelName))); err != nil {
		return nil, fmt.Errorf("parse log level: %w", err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})), nil
}
