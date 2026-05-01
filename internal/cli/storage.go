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
	})
}
