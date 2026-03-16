package storage

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/findings"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
)

type ScanRecord struct {
	Registry           string
	Repository         string
	RequestedReference string
	ResolvedReference  string
	RequestedDigest    string
	Mode               string
	ScannedAt          time.Time
	Tags               []TagRecord
	Targets            []TargetRecord
	DetailedFindings   []findings.DetailedFinding
}

type TagRecord struct {
	Name           string
	RootDigest     string
	ManifestDigest string
	Platform       manifest.Platform
	Status         string
	Error          string
}

type TargetRecord struct {
	Reference         string
	ResolvedReference string
	RequestedDigest   string
	Tags              []string
	Error             string
	Manifests         []ManifestRecord
}

type ManifestRecord struct {
	Digest     string
	RootDigest string
	Platform   manifest.Platform
	Status     string
	Error      string
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
	parsed, err := url.Parse(strings.TrimSpace(c.DatabaseURL))
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("database url must use postgres scheme")
	}

	return nil
}

func validateScanRecord(record ScanRecord) error {
	if strings.TrimSpace(record.Registry) == "" {
		return fmt.Errorf("scan record registry is required")
	}
	if strings.TrimSpace(record.Repository) == "" {
		return fmt.Errorf("scan record repository is required")
	}
	if record.ScannedAt.IsZero() {
		return fmt.Errorf("scan record scanned at is required")
	}

	for _, item := range record.Tags {
		if strings.TrimSpace(item.Name) == "" {
			return fmt.Errorf("tag name is required")
		}
		if !isValidScanStatus(item.Status) {
			return fmt.Errorf("tag %s status is invalid: %s", item.Name, item.Status)
		}
	}

	for _, item := range record.Targets {
		for _, manifest := range item.Manifests {
			if strings.TrimSpace(manifest.Digest) == "" {
				return fmt.Errorf("target manifest digest is required")
			}
			if !isValidScanStatus(manifest.Status) {
				return fmt.Errorf("manifest %s status is invalid: %s", manifest.Digest, manifest.Status)
			}
		}
	}

	for _, item := range record.DetailedFindings {
		if strings.TrimSpace(item.ManifestDigest) == "" {
			return fmt.Errorf("finding manifest digest is required")
		}
		if strings.TrimSpace(item.Fingerprint) == "" {
			return fmt.Errorf("finding fingerprint is required")
		}
	}

	return nil
}

func isValidScanStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "scanned", "failed":
		return true
	default:
		return false
	}
}
