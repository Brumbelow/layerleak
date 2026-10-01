package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
)

func TestPostgresConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		wantErr     bool
	}{
		{
			name:        "valid",
			databaseURL: "postgres://postgres:postgres@localhost:5432/layerleak?sslmode=disable",
		},
		{
			name:        "postgresql scheme",
			databaseURL: "postgresql://postgres:postgres@localhost:5432/layerleak?sslmode=disable",
		},
		{
			name:    "missing",
			wantErr: true,
		},
		{
			name:        "invalid scheme",
			databaseURL: "mysql://root@localhost:3306/layerleak",
			wantErr:     true,
		},
		{
			name:        "missing host",
			databaseURL: "postgres:///layerleak",
			wantErr:     true,
		},
		{
			name:        "missing database",
			databaseURL: "postgres://localhost",
			wantErr:     true,
		},
		{
			name:        "unix socket host in query string",
			databaseURL: "postgres:///layerleak?host=/var/run/postgresql",
		},
		{
			name:        "hostname in query string with verify-full",
			databaseURL: "postgresql:///layerleak?host=db.internal&port=5432&sslmode=verify-full&sslrootcert=/etc/layerleak/ca.pem",
		},
		{
			name:        "blank query string host",
			databaseURL: "postgres:///layerleak?host=%20",
			wantErr:     true,
		},
		{
			name:        "libpq keywords with socket directory",
			databaseURL: "host=/var/run/postgresql dbname=layerleak",
		},
		{
			name:        "libpq keywords with quoted password and spaces around equals",
			databaseURL: "host=localhost port = 5432 dbname=layerleak user=layerleak password='p w\\'d\\\\' sslmode=disable",
		},
		{
			name:        "libpq keywords default host",
			databaseURL: "dbname=layerleak",
		},
		{
			name:        "libpq keywords without dbname",
			databaseURL: "host=localhost user=layerleak",
			wantErr:     true,
		},
		{
			name:        "libpq keywords with empty dbname",
			databaseURL: "host=localhost dbname=",
			wantErr:     true,
		},
		{
			name:        "libpq keywords with unterminated quote",
			databaseURL: "host=localhost dbname='layerleak",
			wantErr:     true,
		},
		{
			name:        "libpq keywords missing equals",
			databaseURL: "host localhost dbname=layerleak",
			wantErr:     true,
		},
		{
			name:        "plain word",
			databaseURL: "layerleak",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PostgresConfig{
				DatabaseURL: tt.databaseURL,
			}.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestPostgresConfigValidateDoesNotEchoMalformedDatabaseURL(t *testing.T) {
	databaseURL := "postgres://layerleak:super-secret-value%ZZ@localhost:5432/layerleak"
	err := (PostgresConfig{DatabaseURL: databaseURL}).Validate()
	if err == nil {
		t.Fatal("Validate() error = nil")
	}
	if err.Error() != "database url is invalid" {
		t.Fatalf("Validate() error = %q", err)
	}
	if strings.Contains(err.Error(), "super-secret-value") || strings.Contains(err.Error(), databaseURL) {
		t.Fatalf("Validate() leaked database URL: %v", err)
	}
}

func TestPostgresConfigValidateDoesNotEchoMalformedKeywordDSN(t *testing.T) {
	dsn := "host=localhost password='super-secret-value dbname=layerleak"
	err := (PostgresConfig{DatabaseURL: dsn}).Validate()
	if err == nil {
		t.Fatal("Validate() error = nil")
	}
	if strings.Contains(err.Error(), "super-secret-value") || strings.Contains(err.Error(), dsn) {
		t.Fatalf("Validate() leaked connection string: %v", err)
	}
}

func TestParseKeywordDSN(t *testing.T) {
	pairs, err := parseKeywordDSN("host=/var/run/postgresql port = 5433 dbname=layerleak password='it\\'s \\\\ spaced' sslmode=disable")
	if err != nil {
		t.Fatalf("parseKeywordDSN() error = %v", err)
	}
	want := map[string]string{
		"host":     "/var/run/postgresql",
		"port":     "5433",
		"dbname":   "layerleak",
		"password": `it's \ spaced`,
		"sslmode":  "disable",
	}
	if len(pairs) != len(want) {
		t.Fatalf("pairs = %v", pairs)
	}
	for key, value := range want {
		if pairs[key] != value {
			t.Fatalf("pairs[%q] = %q, want %q", key, pairs[key], value)
		}
	}
	for _, invalid := range []string{"host", "=x", "host='x", "ho st=x", "host=x =y"} {
		if _, err := parseKeywordDSN(invalid); err == nil {
			t.Fatalf("parseKeywordDSN(%q) error = nil", invalid)
		}
	}
}

func TestIsValidScanStatusAcceptsPartial(t *testing.T) {
	if !isValidScanStatus("partial") {
		t.Fatal("isValidScanStatus(partial) = false")
	}
}

func TestPostgresConfigValidateRejectsInvalidPoolAndTimeoutSettings(t *testing.T) {
	databaseURL := "postgres://postgres:postgres@localhost:5432/layerleak?sslmode=disable"
	tests := []PostgresConfig{
		{DatabaseURL: databaseURL, MaxOpenConns: -1},
		{DatabaseURL: databaseURL, MaxOpenConns: 2, MaxIdleConns: 3},
		{DatabaseURL: databaseURL, ConnMaxLifetime: -time.Second},
		{DatabaseURL: databaseURL, ConnMaxIdleTime: -time.Second},
		{DatabaseURL: databaseURL, QueryTimeout: -time.Second},
		{DatabaseURL: databaseURL, WriteTimeout: -time.Second},
	}
	for index, config := range tests {
		if err := config.Validate(); err == nil {
			t.Fatalf("test %d: Validate() error = nil", index)
		}
	}
}

func TestPostgresConfigDefaults(t *testing.T) {
	config := (PostgresConfig{}).withDefaults()
	if config.MaxOpenConns != 10 || config.MaxIdleConns != 5 {
		t.Fatalf("pool defaults = (%d,%d), want idle connections retained by default", config.MaxOpenConns, config.MaxIdleConns)
	}
	if small := (PostgresConfig{MaxOpenConns: 2}).withDefaults(); small.MaxIdleConns != 2 {
		t.Fatalf("idle default with 2 open connections = %d, want capped at 2", small.MaxIdleConns)
	}
	if explicit := (PostgresConfig{MaxIdleConns: 1}).withDefaults(); explicit.MaxIdleConns != 1 {
		t.Fatalf("explicit idle setting = %d, want preserved", explicit.MaxIdleConns)
	}
	if config.ConnMaxLifetime != 30*time.Minute || config.ConnMaxIdleTime != 5*time.Minute || config.QueryTimeout != 10*time.Second || config.WriteTimeout != 2*time.Minute {
		t.Fatalf("duration defaults = %#v", config)
	}
}

func TestRawSecretCountsTotal(t *testing.T) {
	counts := RawSecretCounts{FindingValues: 2, OccurrenceSnippets: 3}
	if got := counts.Total(); got != 5 {
		t.Fatalf("Total() = %d", got)
	}
}

func TestParsePostgresServerVersionNum(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int
		wantErr bool
	}{
		{
			name: "valid",
			raw:  "160013",
			want: 160013,
		},
		{
			name: "trim whitespace",
			raw:  " 170001 ",
			want: 170001,
		},
		{
			name:    "missing",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "invalid text",
			raw:     "sixteen",
			wantErr: true,
		},
		{
			name:    "negative",
			raw:     "-1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePostgresServerVersionNum(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePostgresServerVersionNum() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parsePostgresServerVersionNum() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateMinimumPostgresServerVersionNum(t *testing.T) {
	tests := []struct {
		name       string
		versionNum int
		wantErr    bool
	}{
		{
			name:       "minimum",
			versionNum: 160013,
		},
		{
			name:       "greater than minimum",
			versionNum: 170002,
		},
		{
			name:       "below minimum",
			versionNum: 160012,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMinimumPostgresServerVersionNum(tt.versionNum)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMinimumPostgresServerVersionNum() error = %v", err)
			}
		})
	}
}

func TestValidateScanRecord(t *testing.T) {
	validRecord := func() ScanRecord {
		return ScanRecord{
			Registry:   "docker.io",
			Repository: "library/app",
			Status:     ScanRunStatusCompleted,
			ResultJSON: []byte(`{"requested_reference":"library/app:latest","status":"redacted"}`),
			ScannedAt:  time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC),
			Tags: []TagRecord{
				{
					Name:           "latest",
					RootDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					ManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Status:         "scanned",
				},
			},
			Targets: []TargetRecord{
				{
					Reference:       "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Manifests: []ManifestRecord{
						{
							Digest:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
							RootDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							Status:     "scanned",
						},
					},
				},
			},
			DetailedFindings: []findings.DetailedFinding{
				{
					Finding: findings.Finding{
						ManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						Fingerprint:    "fingerprint",
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		record  ScanRecord
		wantErr bool
	}{
		{
			name:   "valid",
			record: validRecord(),
		},
		{
			name: "missing repository",
			record: func() ScanRecord {
				item := validRecord()
				item.Repository = ""
				return item
			}(),
			wantErr: true,
		},
		{
			name: "invalid scan status",
			record: func() ScanRecord {
				item := validRecord()
				item.Status = "broken"
				return item
			}(),
			wantErr: true,
		},
		{
			name: "invalid tag status",
			record: func() ScanRecord {
				item := validRecord()
				item.Tags[0].Status = "resolved"
				return item
			}(),
			wantErr: true,
		},
		{
			name: "invalid result json",
			record: func() ScanRecord {
				item := validRecord()
				item.ResultJSON = []byte("{")
				return item
			}(),
			wantErr: true,
		},
		{
			name: "negative counter",
			record: func() ScanRecord {
				item := validRecord()
				item.PartialTargetCount = -1
				return item
			}(),
			wantErr: true,
		},
		{
			name: "missing finding fingerprint",
			record: func() ScanRecord {
				item := validRecord()
				item.DetailedFindings[0].Fingerprint = ""
				return item
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScanRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateScanRecord() error = %v", err)
			}
		})
	}
}
