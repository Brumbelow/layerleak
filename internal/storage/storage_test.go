package storage

import (
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
