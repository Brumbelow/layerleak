package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/manifest"
)

type ScanRecord struct {
	Registry                     string
	Repository                   string
	RequestedReference           string
	ResolvedReference            string
	RequestedDigest              string
	Mode                         string
	TagsEnumerated               int
	TagsResolved                 int
	TagsFailed                   int
	TargetCount                  int
	CompletedTargetCount         int
	FailedTargetCount            int
	PartialTargetCount           int
	ManifestCount                int
	CompletedManifestCount       int
	FailedManifestCount          int
	TotalFindings                int
	UniqueFingerprints           int
	SuppressedFindingsCount      int
	SuppressedUniqueFingerprints int
	Status                       ScanRunStatus
	ErrorMessage                 string
	ResultJSON                   json.RawMessage
	ScannedAt                    time.Time
	Tags                         []TagRecord
	Targets                      []TargetRecord
	DetailedFindings             []findings.DetailedFinding
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
	SaveScan(ctx context.Context, record ScanRecord) (int64, error)
	Name() string
}

type ReadStore interface {
	ListRepositories(ctx context.Context, limit, offset int) ([]RepositorySummary, error)
	ListRepositoryScans(ctx context.Context, registry, repository string, limit, offset int) ([]ScanRunSummary, error)
	ListRepositoryFindings(ctx context.Context, registry, repository string, disposition FindingDispositionFilter, limit, offset int) ([]FindingSummary, error)
	GetScanRun(ctx context.Context, id int64) (ScanRunDetail, error)
	GetFinding(ctx context.Context, id int64) (FindingDetail, error)
}

type RepositorySummary struct {
	Registry    string
	Repository  string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type ScanRunStatus string

const (
	ScanRunStatusCompleted ScanRunStatus = "completed"
	ScanRunStatusPartial   ScanRunStatus = "partial"
	ScanRunStatusFailed    ScanRunStatus = "failed"
)

type ScanRunSummary struct {
	ID                           int64
	RequestedReference           string
	ResolvedReference            string
	RequestedDigest              string
	Mode                         string
	Status                       ScanRunStatus
	ErrorMessage                 string
	ScannedAt                    time.Time
	TagsEnumerated               int
	TagsResolved                 int
	TagsFailed                   int
	TargetCount                  int
	CompletedTargetCount         int
	FailedTargetCount            int
	PartialTargetCount           int
	ManifestCount                int
	CompletedManifestCount       int
	FailedManifestCount          int
	TotalFindings                int
	UniqueFingerprints           int
	SuppressedFindingsCount      int
	SuppressedUniqueFingerprints int
}

type ScanRunDetail struct {
	ScanRunSummary
	Registry   string
	Repository string
	ResultJSON json.RawMessage
}

type FindingDispositionFilter string

// FindingDispositionFilter values are the user-facing filter names exposed by
// the HTTP API. Note that "suppressed" maps to occurrences whose stored
// disposition is the literal string "example" (DispositionExample); the two
// names are intentionally aligned: the API speaks in terms of "actionable" vs
// "suppressed", while persistence speaks in terms of "actionable" vs "example"
// to preserve schema compatibility.
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
	DatabaseURL       string
	PersistRawSecrets bool
	MaxOpenConns      int
	MaxIdleConns      int
	ConnMaxLifetime   time.Duration
	ConnMaxIdleTime   time.Duration
	QueryTimeout      time.Duration
	WriteTimeout      time.Duration
	RequireSchema     bool
}

const (
	defaultMaxOpenConns    = 10
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 5 * time.Minute
	defaultQueryTimeout    = 10 * time.Second
	defaultWriteTimeout    = 2 * time.Minute
)

func NewNoopStore() NoopStore {
	return NoopStore{}
}

func (NoopStore) SaveScan(_ context.Context, _ ScanRecord) (int64, error) {
	return 0, nil
}

func (NoopStore) Name() string {
	return "noop"
}

func (c PostgresConfig) Validate() error {
	c = c.withDefaults()
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("database url is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(c.DatabaseURL))
	if err != nil {
		return fmt.Errorf("database url is invalid")
	}
	if parsed.RawQuery != "" {
		if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
			return fmt.Errorf("database url is invalid")
		}
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("database url must use postgres scheme")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return fmt.Errorf("database url host is required")
	}
	if strings.TrimSpace(parsed.Path) == "" || parsed.Path == "/" {
		return fmt.Errorf("database url name is required")
	}
	if c.MaxOpenConns < 0 {
		return fmt.Errorf("max open connections must be greater than zero")
	}
	if c.MaxIdleConns < 0 {
		return fmt.Errorf("max idle connections must be greater than or equal to zero")
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		return fmt.Errorf("max idle connections must not exceed max open connections")
	}
	if c.ConnMaxLifetime < 0 {
		return fmt.Errorf("connection max lifetime must be greater than zero")
	}
	if c.ConnMaxIdleTime < 0 {
		return fmt.Errorf("connection max idle time must be greater than zero")
	}
	if c.QueryTimeout < 0 {
		return fmt.Errorf("query timeout must be greater than zero")
	}
	if c.WriteTimeout < 0 {
		return fmt.Errorf("write timeout must be greater than zero")
	}

	return nil
}

func (c PostgresConfig) withDefaults() PostgresConfig {
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = defaultMaxOpenConns
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = defaultConnMaxLifetime
	}
	if c.ConnMaxIdleTime == 0 {
		c.ConnMaxIdleTime = defaultConnMaxIdleTime
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = defaultQueryTimeout
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	return c
}

func validateScanRecord(record ScanRecord) error {
	if strings.TrimSpace(record.Registry) == "" {
		return fmt.Errorf("scan record registry is required")
	}
	if strings.TrimSpace(record.Repository) == "" {
		return fmt.Errorf("scan record repository is required")
	}
	if !isValidScanRunStatus(record.Status) {
		return fmt.Errorf("scan record status is invalid: %s", record.Status)
	}
	if !json.Valid(record.ResultJSON) {
		return fmt.Errorf("scan record result json must be valid JSON")
	}
	if record.ScannedAt.IsZero() {
		return fmt.Errorf("scan record scanned at is required")
	}
	for name, value := range map[string]int{
		"tags enumerated":                record.TagsEnumerated,
		"tags resolved":                  record.TagsResolved,
		"tags failed":                    record.TagsFailed,
		"target count":                   record.TargetCount,
		"completed target count":         record.CompletedTargetCount,
		"failed target count":            record.FailedTargetCount,
		"partial target count":           record.PartialTargetCount,
		"manifest count":                 record.ManifestCount,
		"completed manifest count":       record.CompletedManifestCount,
		"failed manifest count":          record.FailedManifestCount,
		"total findings":                 record.TotalFindings,
		"unique fingerprints":            record.UniqueFingerprints,
		"suppressed findings count":      record.SuppressedFindingsCount,
		"suppressed unique fingerprints": record.SuppressedUniqueFingerprints,
	} {
		if value < 0 {
			return fmt.Errorf("scan record %s must be greater than or equal to zero", name)
		}
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
	case "scanned", "partial", "failed":
		return true
	default:
		return false
	}
}

func isValidScanRunStatus(value ScanRunStatus) bool {
	switch value {
	case ScanRunStatusCompleted, ScanRunStatusPartial, ScanRunStatusFailed:
		return true
	default:
		return false
	}
}
