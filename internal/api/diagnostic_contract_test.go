package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// emittedDiagnosticCodes lists every diagnostic code the scanner and the jobs
// layer can put in a result: the fixed codes, each index skip reason, each
// integrity error kind and each limit kind with its _exceeded suffix, plus
// an empty and an unknown code.
func emittedDiagnosticCodes() []string {
	codes := []string{
		"files_skipped_oversize",
		"unsafe_archive_entries_skipped",
		"nested_archive_skipped",
		"raw_retention_truncated",
		"max_findings_exceeded",
		"max_raw_finding_bytes_exceeded",
		"manifest_unsupported",
		"platform_not_found",
		"layer_trailing_data",
		"scan_canceled",
		"manifest_failed",
		string(manifest.SkipReasonUnsupportedManifest),
		string(manifest.SkipReasonPlatform),
		string(manifest.IntegrityInvalidDocument),
		string(manifest.IntegrityInvalidDigest),
		string(manifest.IntegrityDigestMismatch),
		string(manifest.IntegritySizeMismatch),
		string(manifest.IntegrityMediaTypeMismatch),
		string(manifest.IntegrityPlatformMismatch),
		string(manifest.IntegrityUnsupportedDigestAlgorithm),
	}
	kinds := []limits.Kind{
		limits.KindLayerBytes, limits.KindLayerEntries, limits.KindManifestBytes, limits.KindConfigBytes,
		limits.KindTagResponseBytes, limits.KindRepositoryTags, limits.KindRepositoryTargets,
		"image_manifests", "image_layer_bytes", "image_entries", "retained_bytes",
		"docker_config_bytes", "auth_response_bytes", "auth_token_cache_entries", "auth_token_cache_bytes",
	}
	for _, kind := range kinds {
		codes = append(codes, string(kind)+"_exceeded")
	}
	return append(codes, "", "code_added_after_this_test")
}

// openAPIDiagnosticMessage reads components.schemas.Diagnostic.message from
// web/docs/openapi.yaml: its enum values and its folded description.
func openAPIDiagnosticMessage(t *testing.T) ([]string, string) {
	t.Helper()
	spec, err := os.ReadFile(filepath.Join("..", "..", "web", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(spec), "\n")
	start := slices.Index(lines, "    Diagnostic:")
	if start < 0 {
		t.Fatal("web/docs/openapi.yaml declares no components.schemas.Diagnostic")
	}
	var values []string
	var description strings.Builder
	inMessage, inEnum, inDescription := false, false, false
	for _, line := range lines[start+1:] {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "      ") {
			break // the next schema or section
		}
		if strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         ") {
			inMessage = line == "        message:"
			inEnum, inDescription = false, false
			continue
		}
		if !inMessage {
			continue
		}
		switch {
		case strings.HasPrefix(line, "          enum:"):
			inEnum, inDescription = true, false
		case strings.HasPrefix(line, "          description:"):
			inDescription, inEnum = true, false
		case inEnum && strings.HasPrefix(line, "            - "):
			values = append(values, strings.TrimPrefix(line, "            - "))
		case inDescription && strings.HasPrefix(line, "            "):
			description.WriteString(strings.TrimSpace(line) + " ")
		default:
			inEnum, inDescription = false, false
		}
	}
	if len(values) == 0 {
		t.Fatal("no Diagnostic.message enum parsed from web/docs/openapi.yaml")
	}
	return values, description.String()
}

// TestDiagnosticMessagesMatchOpenAPIEnum keeps the API's diagnostic sanitiser
// and the closed Diagnostic.message enum in lockstep: every code the scanner
// can emit, and an unknown one, sanitises to a documented message; every
// documented message is one the handler can return; and the description
// names each code that has its own message.
func TestDiagnosticMessagesMatchOpenAPIEnum(t *testing.T) {
	enum, description := openAPIDiagnosticMessage(t)
	documented := map[string]bool{}
	for _, value := range enum {
		documented[value] = true
	}

	codes := emittedDiagnosticCodes()
	for code := range diagnosticMessages {
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	produced := map[string]bool{}
	for _, code := range codes {
		diagnostic := map[string]any{"code": code, "message": "synthetic scanner text for " + code}
		document, err := json.Marshal(map[string]any{
			"diagnostics": []any{diagnostic},
			"targets":     []any{map[string]any{"platform_results": []any{map[string]any{"diagnostics": []any{diagnostic}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		sanitized, err := sanitizeResultJSON(document)
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		type messageOnly struct {
			Message string `json:"message"`
		}
		var result struct {
			Diagnostics []messageOnly `json:"diagnostics"`
			Targets     []struct {
				PlatformResults []struct {
					Diagnostics []messageOnly `json:"diagnostics"`
				} `json:"platform_results"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(sanitized, &result); err != nil {
			t.Fatal(err)
		}
		want := safeDiagnosticMessage(code)
		for _, message := range []string{result.Diagnostics[0].Message, result.Targets[0].PlatformResults[0].Diagnostics[0].Message} {
			if message != want {
				t.Errorf("code %q: sanitised message %q, want %q", code, message, want)
			}
			if !documented[message] {
				t.Errorf("code %q: the handler returns %q, which the OpenAPI Diagnostic.message enum does not list", code, message)
			}
		}
		produced[want] = true
		if want != "scan step failed" && !strings.Contains(description, "`"+code+"`") {
			t.Errorf("the OpenAPI Diagnostic.message description does not name code %q, which maps to %q", code, want)
		}
	}
	// The description names the mapped codes in enum order.
	var named []string
	for index, part := range strings.Split(description, "`") {
		if index%2 == 1 && part != "code" && !strings.Contains(part, " ") {
			named = append(named, part)
		}
	}
	if len(named) != len(enum)-1 || enum[len(enum)-1] != "scan step failed" {
		t.Errorf("the OpenAPI Diagnostic.message description names %d codes for %d enum values; the enum must end with \"scan step failed\"", len(named), len(enum))
	} else {
		for index, code := range named {
			if got := safeDiagnosticMessage(code); got != enum[index] {
				t.Errorf("the OpenAPI description maps %q to enum value %q, the handler returns %q", code, enum[index], got)
			}
		}
	}
	for _, value := range enum {
		if !produced[value] {
			t.Errorf("the OpenAPI Diagnostic.message enum lists %q, which no diagnostic code produces", value)
		}
	}
}
