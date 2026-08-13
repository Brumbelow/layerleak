package scanservice

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanner"
)

func TestBuildScanRecordSanitizesErrorsAndPersistsPartialStatus(t *testing.T) {
	const sensitive = "Authorization: Bearer registry-secret-value"
	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result := jobs.Result{
		Status:             jobs.ResultStatusPartial,
		RequestedReference: reference.Original,
		Repository:         reference.Repository,
		TargetCount:        1,
		PartialTargetCount: 1,
		ManifestCount:      1,
		TagResults: []jobs.TagResult{
			{Tag: "broken", Status: "failed", Error: sensitive},
		},
		Targets: []jobs.TargetResult{
			{
				Status:          jobs.ResultStatusPartial,
				Reference:       "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RequestedDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Tags:            []string{"latest"},
				Error:           sensitive,
				PlatformResults: []scanner.PlatformResult{
					{
						Status:         scanner.ResultStatusPartial,
						Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
						ManifestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						Error:          sensitive,
						Diagnostics:    []scanner.Diagnostic{{Code: "manifest_failed", Message: sensitive}},
					},
				},
			},
		},
		Diagnostics: []scanner.Diagnostic{{Code: "manifest_failed", Message: sensitive}},
	}
	scanErr := errors.New(sensitive)

	record, err := BuildScanRecord(reference, result, time.Now(), scanErr)
	if err != nil {
		t.Fatalf("BuildScanRecord() error = %v", err)
	}
	if strings.Contains(record.ErrorMessage, sensitive) || strings.Contains(string(record.ResultJSON), sensitive) {
		t.Fatalf("record leaked operational error: %#v %s", record, record.ResultJSON)
	}
	if record.ErrorMessage != "scan did not complete successfully" {
		t.Fatalf("record.ErrorMessage = %q", record.ErrorMessage)
	}
	if len(record.Targets) != 1 || len(record.Targets[0].Manifests) != 1 {
		t.Fatalf("record.Targets = %#v", record.Targets)
	}
	if record.Targets[0].Manifests[0].Status != "partial" {
		t.Fatalf("manifest status = %q", record.Targets[0].Manifests[0].Status)
	}
	if strings.Contains(record.Targets[0].Error, sensitive) || strings.Contains(record.Targets[0].Manifests[0].Error, sensitive) {
		t.Fatalf("target record leaked operational error: %#v", record.Targets[0])
	}
	if record.Targets[0].Error != "scan step failed" || record.Targets[0].Manifests[0].Error != "scan step failed" {
		t.Fatalf("target record errors = %#v", record.Targets[0])
	}
	if len(record.Tags) != 2 || record.Tags[0].Status != "failed" || record.Tags[1].Status != "partial" {
		t.Fatalf("record.Tags = %#v", record.Tags)
	}
	if strings.Contains(record.Tags[0].Error, sensitive) || strings.Contains(record.Tags[1].Error, sensitive) {
		t.Fatalf("tag records leaked operational error: %#v", record.Tags)
	}
	if result.Targets[0].Error != sensitive || result.Targets[0].PlatformResults[0].Diagnostics[0].Message != sensitive {
		t.Fatal("BuildScanRecord() mutated the returned scan result")
	}
	wrapped := wrapScanError(scanErr)
	if !errors.Is(wrapped, scanErr) {
		t.Fatal("wrapped scan error no longer preserves errors.Is semantics")
	}
	var serviceErr *Error
	if !errors.As(wrapped, &serviceErr) || serviceErr.Phase != ErrorPhaseScan {
		t.Fatalf("wrapped scan error type = %#v", serviceErr)
	}
}
