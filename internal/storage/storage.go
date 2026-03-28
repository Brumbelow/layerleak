package storage

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
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

type ReadStore interface {
	ListRepositories(ctx context.Context, limit, offset int) ([]RepositorySummary, error)
	ListRepositoryFindings(ctx context.Context, repository string, disposition FindingDispositionFilter, limit, offset int) ([]FindingSummary, error)
	GetFinding(ctx context.Context, id int64) (FindingDetail, error)
}

type RepositorySummary struct {
	Registry    string
	Repository  string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type FindingDispositionFilter string

const (
	FindingDispositionAll        FindingDispositionFilter = "all"
	FindingDispositionActionable FindingDispositionFilter = "actionable"
	FindingDispositionSuppressed FindingDispositionFilter = "suppressed"
)

type FindingSummary struct {
	ID                        int64
	ManifestDigest            string
	Fingerprint               string
	RedactedValue             string
	FirstSeenAt               time.Time
	LastSeenAt                time.Time
	OccurrenceCount           int
	ActionableOccurrenceCount int
	SuppressedOccurrenceCount int
	Detectors                 []string
}

type FindingDetail struct {
	FindingSummary
	Occurrences []FindingOccurrence
}

type FindingOccurrence struct {
	DetectorName        string
	Confidence          string
	Disposition         findings.Disposition
	DispositionReason   findings.DispositionReason
	SourceType          findings.SourceType
	Platform            manifest.Platform
	FilePath            string
	LayerDigest         string
	Key                 string
	LineNumber          int
	ContextSnippet      string
	SourceLocation      string
	MatchStart          int
	MatchEnd            int
	PresentInFinalImage bool
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
}

var ErrNotFound = errors.New("storage record not found")

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
