package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

const apiShutdownTimeout = 30 * time.Second

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required for the API")
	}

	store, err := storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL:       cfg.DatabaseURL,
		PersistRawSecrets: cfg.PersistRawSecrets,
	})
	if err != nil {
		return err
	}
	defer store.Close()

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           NewHandler(scanservice.New(cfg, store), store),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), apiShutdownTimeout)
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
