package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
)

type ScanRecord struct {
	ManifestDigest string
	ImageReference string
	Findings       []findings.Finding
	ScannedAt      time.Time
}

type Store interface {
	SaveScan(ctx context.Context, record ScanRecord) error
	Name() string
}

type NoopStore struct{}

type PostgresConfig struct {
	DatabaseURL string
}

func NewNoopStore() NoopStore {
	return NoopStore{}
}

func (NoopStore) SaveScan(ctx context.Context, record ScanRecord) error {
	return nil
}

func (NoopStore) Name() string {
	return "noop"
}

func (c PostgresConfig) Validate() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("database url is required")
	}

	return nil
}
