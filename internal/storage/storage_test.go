package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/findings"
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
	if config.MaxOpenConns != 10 || config.MaxIdleConns != 0 {
		t.Fatalf("pool defaults = (%d,%d)", config.MaxOpenConns, config.MaxIdleConns)
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
