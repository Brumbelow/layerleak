package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
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

// ReadStore serves the API's read endpoints. Each list method pages either by
// offset or, when the cursor argument is non-nil, by keyset: the page then
// holds the rows strictly after the cursor in the endpoint's total ordering,
// so deep pages cost no more than the first. Offset still applies on top of a
// cursor and callers normally pass zero with one.
type ReadStore interface {
	ListRepositories(ctx context.Context, limit, offset int, after *RepositoryCursor) ([]RepositorySummary, error)
	ListRepositoryScans(ctx context.Context, registry, repository string, limit, offset int, after *ScanRunCursor) ([]ScanRunSummary, error)
	ListRepositoryFindings(ctx context.Context, registry, repository string, disposition FindingDispositionFilter, limit, offset int, after *FindingCursor) ([]FindingSummary, error)
	GetScanRun(ctx context.Context, id int64) (ScanRunDetail, error)
	GetFinding(ctx context.Context, id int64) (FindingDetail, error)
}

// RepositoryCursor is a keyset position in ListRepositories, whose ordering is
// last_seen_at DESC, repository ASC, registry ASC: the next page starts
// strictly after the row with these values. (registry, repository) is unique.
type RepositoryCursor struct {
	LastSeenAt time.Time
	Repository string
	Registry   string
}

// ScanRunCursor is a keyset position in ListRepositoryScans, whose ordering
// is scanned_at DESC, id DESC.
type ScanRunCursor struct {
	ScannedAt time.Time
	ID        int64
}

// FindingCursor is a keyset position in ListRepositoryFindings, whose ordering
// is last_seen_at DESC, id DESC.
type FindingCursor struct {
	LastSeenAt time.Time
	ID         int64
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

// DefaultWriteTimeout bounds one SaveScan transaction when PostgresConfig
// leaves WriteTimeout unset. Callers that persist a finished scan under a
// context detached from the request (scanservice) use it as their fallback so
// the write phase is never unbounded.
const DefaultWriteTimeout = 2 * time.Minute

const (
	defaultMaxOpenConns = 10
	// defaultMaxIdleConns mirrors LAYERLEAK_DATABASE_MAX_IDLE_CONNS in
	// internal/config; database/sql treats 0 as "retain no idle connections",
	// which made every statement outside a transaction dial and authenticate
	// anew for callers that left the field unset.
	defaultMaxIdleConns    = 5
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 5 * time.Minute
	defaultQueryTimeout    = 10 * time.Second
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
	dsn := strings.TrimSpace(c.DatabaseURL)
	if dsn == "" {
		return fmt.Errorf("database url is required")
	}
	// lib/pq accepts two grammars: a postgres:// URL and libpq keyword/value
	// pairs. Neither error path echoes the value, which may carry a password.
	if strings.Contains(dsn, "://") {
		if err := validateDatabaseURL(dsn); err != nil {
			return err
		}
	} else if err := validateKeywordDSN(dsn); err != nil {
		return err
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

func validateDatabaseURL(dsn string) error {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("database url is invalid")
	}
	query := url.Values{}
	if parsed.RawQuery != "" {
		query, err = url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return fmt.Errorf("database url is invalid")
		}
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("database url must use postgres scheme")
	}
	// The host may live in the query string instead of the authority, which
	// is how libpq addresses unix sockets (host=/var/run/postgresql) and how
	// Cloud SQL Auth Proxy style deployments are configured.
	if strings.TrimSpace(parsed.Hostname()) == "" && strings.TrimSpace(query.Get("host")) == "" && strings.TrimSpace(query.Get("hostaddr")) == "" {
		return fmt.Errorf("database url host is required")
	}
	if (strings.TrimSpace(parsed.Path) == "" || parsed.Path == "/") && strings.TrimSpace(query.Get("dbname")) == "" {
		return fmt.Errorf("database url name is required")
	}
	return nil
}

func validateKeywordDSN(dsn string) error {
	pairs, err := parseKeywordDSN(dsn)
	if err != nil {
		return fmt.Errorf("database connection string is invalid")
	}
	if strings.TrimSpace(pairs["dbname"]) == "" {
		return fmt.Errorf("database connection string dbname is required")
	}
	return nil
}

// parseKeywordDSN parses a libpq keyword/value connection string such as
// "host=/var/run/postgresql dbname=layerleak password='p w'" into its pairs.
// It mirrors libpq's grammar: whitespace-separated key=value pairs, optional
// whitespace around '=', values either single-quoted (with \' and \\ escapes)
// or an unquoted run up to the next whitespace, and an empty value allowed.
func parseKeywordDSN(value string) (map[string]string, error) {
	pairs := make(map[string]string)
	index := 0
	skipSpaces := func() {
		for index < len(value) && isDSNSpace(value[index]) {
			index++
		}
	}
	for {
		skipSpaces()
		if index >= len(value) {
			return pairs, nil
		}
		start := index
		for index < len(value) && isDSNKeyByte(value[index]) {
			index++
		}
		if index == start {
			return nil, fmt.Errorf("connection string key is missing")
		}
		key := value[start:index]
		skipSpaces()
		if index >= len(value) || value[index] != '=' {
			return nil, fmt.Errorf("connection string key %q is not followed by '='", key)
		}
		index++
		skipSpaces()
		var builder strings.Builder
		if index < len(value) && value[index] == '\'' {
			index++
			terminated := false
			for index < len(value) {
				character := value[index]
				index++
				if character == '\\' && index < len(value) {
					builder.WriteByte(value[index])
					index++
					continue
				}
				if character == '\'' {
					terminated = true
					break
				}
				builder.WriteByte(character)
			}
			if !terminated {
				return nil, fmt.Errorf("connection string value for %q has an unterminated quote", key)
			}
		} else {
			for index < len(value) && !isDSNSpace(value[index]) {
				character := value[index]
				index++
				if character == '\\' && index < len(value) {
					builder.WriteByte(value[index])
					index++
					continue
				}
				builder.WriteByte(character)
			}
		}
		pairs[key] = builder.String()
	}
}

func isDSNSpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isDSNKeyByte(character byte) bool {
	return character == '_' || (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

func (c PostgresConfig) withDefaults() PostgresConfig {
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = defaultMaxOpenConns
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = min(defaultMaxIdleConns, c.MaxOpenConns)
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
		c.WriteTimeout = DefaultWriteTimeout
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
