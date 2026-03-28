package cli

import (
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

func newStore(cfg config.Config) (storage.Store, error) {
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return storage.NewNoopStore(), nil
	}

	return storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL: cfg.DatabaseURL,
	})
}

func buildScanRecord(reference manifest.Reference, result jobs.Result, scannedAt time.Time) storage.ScanRecord {
	return scanservice.BuildScanRecord(reference, result, scannedAt)
}
