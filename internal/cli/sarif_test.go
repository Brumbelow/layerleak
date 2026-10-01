package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/sarif"
	"github.com/brumbelow/layerleak/v3/internal/scanner"
)

func TestSARIFRulesAndEncodingExactOutput(t *testing.T) {
	result := jobs.Result{
		ResultSchemaVersion: jobs.ResultSchemaVersion,
		ScannedAt:           time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC),
		Scanner:             jobs.ScannerInfo{Name: jobs.ScannerName, Version: "v3.0.0-test"},
		Status:              jobs.ResultStatusCompleted,
		RequestedReference:  "library/app:latest",
		Repository:          "library/app",
		Mode:                "reference",
		ResolvedReference:   "docker.io/library/app@sha256:aaaa",
		RequestedDigest:     "sha256:aaaa",
		TargetCount:         1, CompletedTargetCount: 1, ManifestCount: 1, CompletedManifestCount: 1,
		Findings: []findings.Finding{{
			DetectorName: "github_token", Confidence: "high", Disposition: findings.DispositionActionable,
			SourceType: findings.SourceTypeEnv, ManifestDigest: "sha256:aaaa",
			Platform: manifest.Platform{OS: "linux", Architecture: "amd64"}, Key: "GH_TOKEN",
			RedactedValue: "ghp********", Fingerprint: "ffff", ContextSnippet: "GH_TOKEN=ghp********",
			MatchStart: 9, MatchEnd: 49, PresentInFinalImage: true,
		}},
		TotalFindings: 1, UniqueFingerprints: 1,
		Coverage: scanner.Coverage{Complete: true, LayersSeen: 1, LayersCompleted: 1, MetadataValuesScanned: 1},
	}
	var output bytes.Buffer
	if err := sarif.Encode(&output, sarif.FromResult(result, sarif.Options{ToolVersion: "v3.0.0-test", Rules: sarifRules([]string{"aws_access_key_id", "github_token"})})); err != nil {
		t.Fatal(err)
	}
	const want = `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "layerleak",
          "version": "v3.0.0-test",
          "semanticVersion": "3.0.0-test",
          "informationUri": "https://github.com/Brumbelow/layerleak",
          "rules": [
            {
              "id": "aws_access_key_id",
              "name": "aws_access_key_id",
              "shortDescription": {
                "text": "Likely secret matched by the aws_access_key_id detector."
              },
              "helpUri": "https://github.com/Brumbelow/layerleak",
              "defaultConfiguration": {
                "level": "warning"
              },
              "properties": {
                "tags": [
                  "security",
                  "secret"
                ]
              }
            },
            {
              "id": "github_token",
              "name": "github_token",
              "shortDescription": {
                "text": "Likely secret matched by the github_token detector."
              },
              "helpUri": "https://github.com/Brumbelow/layerleak",
              "defaultConfiguration": {
                "level": "warning"
              },
              "properties": {
                "tags": [
                  "security",
                  "secret"
                ]
              }
            }
          ]
        }
      },
      "automationDetails": {
        "id": "layerleak/docker.io/library/app@sha256:aaaa"
      },
      "invocations": [
        {
          "executionSuccessful": true
        }
      ],
      "originalUriBaseIds": {
        "IMAGE": {
          "uri": "oci://docker.io/library/app@sha256:aaaa/",
          "description": {
            "text": "Root filesystem of docker.io/library/app@sha256:aaaa"
          }
        }
      },
      "results": [
        {
          "ruleId": "github_token",
          "ruleIndex": 1,
          "level": "error",
          "message": {
            "text": "Likely secret matched by the github_token detector (high confidence) in environment variable GH_TOKEN. Redacted value: ghp********."
          },
          "locations": [
            {
              "logicalLocations": [
                {
                  "name": "GH_TOKEN",
                  "fullyQualifiedName": "env:GH_TOKEN",
                  "kind": "environmentVariable"
                }
              ]
            }
          ],
          "partialFingerprints": {
            "layerleak/fingerprint/v1": "ffff"
          },
          "properties": {
            "confidence": "high",
            "detector_name": "github_token",
            "disposition": "actionable",
            "key": "GH_TOKEN",
            "manifest_digest": "sha256:aaaa",
            "match_end": 49,
            "match_start": 9,
            "platform": "linux/amd64",
            "present_in_final_image": true,
            "source_type": "env"
          }
        }
      ],
      "properties": {
        "completed_manifest_count": 1,
        "completed_target_count": 1,
        "coverage": {
          "complete": true,
          "layers_seen": 1,
          "layers_completed": 1,
          "files_seen": 0,
          "files_scanned": 0,
          "files_skipped_oversize": 0,
          "files_excluded_binary": 0,
          "entries_skipped_unsafe": 0,
          "metadata_values_scanned": 1,
          "expanded_layer_bytes": 0,
          "retained_bytes": 0,
          "detector_input_bytes_scanned": 0
        },
        "failed_manifest_count": 0,
        "failed_target_count": 0,
        "manifest_count": 1,
        "mode": "reference",
        "partial_target_count": 0,
        "repository": "library/app",
        "requested_digest": "sha256:aaaa",
        "requested_reference": "library/app:latest",
        "resolved_reference": "docker.io/library/app@sha256:aaaa",
        "result_schema_version": 2,
        "status": "completed",
        "suppressed_findings_count": 0,
        "target_count": 1,
        "total_findings": 1,
        "unique_fingerprints": 1
      }
    }
  ]
}
`
	if output.String() != want {
		t.Fatalf("SARIF output mismatch\ngot:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestScanCommandSARIFFormatWritesCatalogAndHonoursOutput(t *testing.T) {
	installExitFixture(t, exitFixtureFinding)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "1048576")
	target := filepath.Join(t.TempDir(), "scan.sarif.json")
	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetContext(context.Background())
	command.SetArgs([]string{"scan", "library/app:latest", "--format", "sarif", "--progress", "off", "--output", target})
	err := command.Execute()
	var coded interface{ ExitCode() int }
	if err == nil || !errors.As(err, &coded) || coded.ExitCode() != exitCodeFindings {
		t.Fatalf("sarif scan exit = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("--output did not redirect SARIF away from stdout: %q", stdout.String())
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string            `json:"name"`
					Version string            `json:"version"`
					Rules   []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &log); err != nil {
		t.Fatalf("SARIF output is not JSON: %v\n%s", err, body)
	}
	if log.Version != sarif.Version || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != sarif.ToolName || log.Runs[0].Tool.Driver.Version != effectiveVersion() {
		t.Fatalf("SARIF header = %+v", log)
	}
	if catalog := detectors.Default().Catalog(); len(log.Runs[0].Tool.Driver.Rules) != len(catalog) {
		t.Fatalf("rules = %d, want every catalog detector (%d)", len(log.Runs[0].Tool.Driver.Rules), len(catalog))
	}
	if len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].RuleID != "github_token" {
		t.Fatalf("results = %+v", log.Runs[0].Results)
	}
	if strings.Contains(string(body), "ghp_123456789012345678901234567890123456") {
		t.Fatal("SARIF output leaked the raw secret")
	}
	assertPrivateArtifacts(t, target)
}
