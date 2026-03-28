package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required for the API")
	}

	store, err := storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL: cfg.DatabaseURL,
	})
	if err != nil {
		return err
	}
	defer store.Close()

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           NewHandler(scanservice.New(cfg, store), store),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
