package cli

import (
	"strings"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/storage"
)

func newStore(cfg config.Config) (storage.Store, error) {
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return storage.NewNoopStore(), nil
	}

	return storage.NewPostgresStore(storage.PostgresConfig{
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
}
