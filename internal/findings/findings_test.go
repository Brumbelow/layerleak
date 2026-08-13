package findings

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/manifest"
)

func TestRedact(t *testing.T) {
	got := Redact("ghp_123456789012345678901234567890123456")
	if got == "ghp_123456789012345678901234567890123456" {
		t.Fatal("Redact() returned raw value")
	}

	if !strings.HasPrefix(got, "ghp") {
		t.Fatalf("Redact() = %q", got)
	}
}

func TestFingerprintStable(t *testing.T) {
	left := Fingerprint("same-value")
	right := Fingerprint("same-value")
	if left != right {
		t.Fatalf("Fingerprint() mismatch: %q != %q", left, right)
	}
}

func TestNormalize(t *testing.T) {
	content := "token=ghp_123456789012345678901234567890123456"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := Normalize(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform: manifest.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		SourceType:          SourceTypeEnv,
		Key:                 "TOKEN",
		Content:             content,
		PresentInFinalImage: true,
	}, match)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if finding.DetectorName != "github_token" {
		t.Fatalf("finding.DetectorName = %q", finding.DetectorName)
	}

	if finding.RedactedValue == match.Value {
		t.Fatal("finding.RedactedValue leaked raw value")
	}

	if strings.Contains(finding.ContextSnippet, match.Value) {
		t.Fatal("finding.ContextSnippet leaked raw value")
	}
}

func TestNormalizeDetailed(t *testing.T) {
	content := "token=ghp_123456789012345678901234567890123456"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform: manifest.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		SourceType:          SourceTypeEnv,
		Key:                 "TOKEN",
		Content:             content,
		PresentInFinalImage: true,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.Value != match.Value {
		t.Fatalf("finding.Value = %q", finding.Value)
	}

	if !strings.Contains(finding.RawSnippet, match.Value) {
		t.Fatalf("finding.RawSnippet = %q", finding.RawSnippet)
	}

	if finding.SourceLocation != "env:TOKEN" {
		t.Fatalf("finding.SourceLocation = %q", finding.SourceLocation)
	}
}

func TestNormalizeDetailedClassifiesExampleTestPath(t *testing.T) {
	content := "TOKEN=ghp_123456789012345678901234567890123456"
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      6,
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
		SourceType:     SourceTypeFileFinal,
		FilePath:       "app/tests/.env",
		Content:        content,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.Disposition != DispositionExample {
		t.Fatalf("finding.Disposition = %q", finding.Disposition)
	}
	if finding.DispositionReason != DispositionReasonTestPath {
		t.Fatalf("finding.DispositionReason = %q", finding.DispositionReason)
	}
}

func TestNormalizeDetailedSetsLineNumber(t *testing.T) {
	content := "one\ntwo\ntoken=ghp_123456789012345678901234567890123456"
	start := strings.Index(content, "ghp_123456789012345678901234567890123456")
	match := detectors.Match{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      start,
		End:        start + len("ghp_123456789012345678901234567890123456"),
		Confidence: detectors.ConfidenceHigh,
	}

	finding, err := NormalizeDetailed(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Platform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
		SourceType:     SourceTypeEnv,
		Key:            "TOKEN",
		Content:        content,
	}, match)
	if err != nil {
		t.Fatalf("NormalizeDetailed() error = %v", err)
	}

	if finding.LineNumber != 3 {
		t.Fatalf("finding.LineNumber = %d", finding.LineNumber)
	}
}

func TestShouldSuppressFilePath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "test directory", filePath: "app/test/.env", want: true},
		{name: "tests directory", filePath: "app/tests/.env", want: true},
		{name: "case insensitive directory", filePath: "app/Test/.env", want: true},
		{name: "windows separator", filePath: `app\tests\.env`, want: true},
		{name: "filename only", filePath: "app_test.go", want: false},
		{name: "substring only", filePath: "app/latest/.env", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSuppressFilePath(tt.filePath); got != tt.want {
				t.Fatalf("ShouldSuppressFilePath(%q) = %t, want %t", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDeduplicateDetailedPreservesDistinctSourceLocations(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("z.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("a.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].FilePath != "a.env" || deduped[1].FilePath != "z.env" {
		t.Fatalf("deduped file paths = %q, %q", deduped[0].FilePath, deduped[1].FilePath)
	}
}

func TestDeduplicateDetailedPreservesDistinctDetectors(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("app.env", "z_detector", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("app.env", "a_detector", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}

func TestDeduplicateDetailedPreservesDistinctPlatformAndLayerProvenance(t *testing.T) {
	base := testDetailedFinding("app.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56")
	base.LayerDigest = "sha256:layer-one"
	differentLayer := base
	differentLayer.LayerDigest = "sha256:layer-two"
	differentPlatform := base
	differentPlatform.Platform.Architecture = "arm64"

	deduped := DeduplicateDetailed([]DetailedFinding{base, differentLayer, differentPlatform})
	if len(deduped) != 3 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	public := Deduplicate([]Finding{base.PublicFinding(), differentLayer.PublicFinding(), differentPlatform.PublicFinding()})
	if len(public) != 3 {
		t.Fatalf("len(public) = %d", len(public))
	}
}

func TestDeduplicateKeysDoNotCollideOnDelimiterBearingProvenance(t *testing.T) {
	first := testDetailedFinding("x|y", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56")
	first.LayerDigest = "z"
	first.SourceLocation = "file:x|y"
	second := first
	second.FilePath = "x"
	second.LayerDigest = "y|z"
	second.SourceLocation = "file:x"

	if got := len(DeduplicateDetailed([]DetailedFinding{first, second})); got != 2 {
		t.Fatalf("len(DeduplicateDetailed()) = %d", got)
	}
	if got := len(Deduplicate([]Finding{first.PublicFinding(), second.PublicFinding()})); got != 2 {
		t.Fatalf("len(Deduplicate()) = %d", got)
	}
}

func TestNormalizeDetailedRedactsSecretsFromMetadataKeyAndSourceLocation(t *testing.T) {
	secret := "ghp_123456789012345678901234567890123456"
	content := secret + "=x"
	match := detectors.Match{Detector: "github_token", Value: secret, Start: 0, End: len(secret), Confidence: detectors.ConfidenceHigh}

	finding, err := NormalizeDetailedWithMatches(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeEnv,
		Key:            secret,
		Content:        content,
	}, match, []detectors.Match{match})
	if err != nil {
		t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
	}
	if strings.Contains(finding.Key, secret) || strings.Contains(finding.SourceLocation, secret) {
		t.Fatalf("public provenance leaked secret: key=%q source=%q", finding.Key, finding.SourceLocation)
	}
	if finding.Value != secret {
		t.Fatalf("finding.Value = %q", finding.Value)
	}
}

func TestNormalizeDetailedRedactsSecretsFromFilePathAndSourceLocation(t *testing.T) {
	secret := "sk-" + "or-v1-" + strings.Repeat("a", 64)
	match := detectors.Match{Detector: "openrouter_api_key", Value: secret, Start: 0, End: len(secret), Confidence: detectors.ConfidenceHigh}

	finding, err := NormalizeDetailedWithMatches(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeFileFinal,
		FilePath:       "secrets/" + secret,
		Content:        secret,
	}, match, []detectors.Match{match})
	if err != nil {
		t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
	}
	for field, value := range map[string]string{
		"file path":       finding.FilePath,
		"source location": finding.SourceLocation,
		"context":         finding.ContextSnippet,
	} {
		if strings.Contains(value, secret) {
			t.Fatalf("%s contains raw secret: %q", field, value)
		}
	}
}

func TestDetailedNormalizerBoundsLargeMetadataProvenanceWithManyMatches(t *testing.T) {
	input, matches := manyMatchNormalizationFixture(4000)
	input.Key = strings.Repeat("metadata-世界/", 5000)

	normalizer, err := NewDetailedNormalizer(input, matches)
	if err != nil {
		t.Fatalf("NewDetailedNormalizer() error = %v", err)
	}
	if len(normalizer.metadataKey) > MaxPublicProvenanceBytes {
		t.Fatalf("len(normalizer.metadataKey) = %d", len(normalizer.metadataKey))
	}
	if !utf8.ValidString(normalizer.metadataKey) {
		t.Fatalf("normalizer.metadataKey is not valid UTF-8: %q", normalizer.metadataKey)
	}
	if !strings.Contains(normalizer.metadataKey, "...[sha256:") {
		t.Fatalf("normalizer.metadataKey = %q", normalizer.metadataKey)
	}

	for index, match := range matches {
		finding, err := normalizer.NormalizeWithRaw(match, false)
		if err != nil {
			t.Fatalf("NormalizeWithRaw(%d) error = %v", index, err)
		}
		for field, value := range map[string]string{
			"key":             finding.Key,
			"source location": finding.SourceLocation,
		} {
			if len(value) > MaxPublicProvenanceBytes {
				t.Fatalf("%s length = %d", field, len(value))
			}
			if !utf8.ValidString(value) {
				t.Fatalf("%s is not valid UTF-8: %q", field, value)
			}
		}
	}

	otherInput := input
	otherInput.Key += "different"
	other, err := NewDetailedNormalizer(otherInput, matches)
	if err != nil {
		t.Fatalf("NewDetailedNormalizer(other) error = %v", err)
	}
	if normalizer.metadataKey == other.metadataKey {
		t.Fatal("distinct long metadata keys produced the same public provenance")
	}
}

func TestDetailedNormalizerRedactsSecretDetectedInLargeMetadataKeyContent(t *testing.T) {
	secret := "ghp_123456789012345678901234567890123456"
	key := strings.Repeat("metadata/", 80) + secret
	content := key + "=value " + secret
	firstStart := strings.Index(content, secret)
	secondStart := strings.LastIndex(content, secret)
	matches := []detectors.Match{
		{Detector: "github_token", Value: secret, Start: firstStart, End: firstStart + len(secret), Confidence: detectors.ConfidenceHigh},
		{Detector: "github_token", Value: secret, Start: secondStart, End: secondStart + len(secret), Confidence: detectors.ConfidenceHigh},
	}

	normalizer, err := NewDetailedNormalizer(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeLabel,
		Key:            key,
		Content:        content,
	}, matches)
	if err != nil {
		t.Fatalf("NewDetailedNormalizer() error = %v", err)
	}
	finding, err := normalizer.Normalize(matches[1])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if strings.Contains(finding.Key, secret) || strings.Contains(finding.SourceLocation, secret) {
		t.Fatalf("public provenance leaked secret: key=%q source=%q", finding.Key, finding.SourceLocation)
	}
	if !strings.Contains(finding.Key, provenanceDigestSuffix(strings.Replace(key, secret, "[REDACTED]", 1))) {
		t.Fatalf("finding.Key used the wrong truncation hash: %q", finding.Key)
	}
}

func TestDetailedNormalizerBoundsSourceLocationAtUTF8Boundary(t *testing.T) {
	secret := "ghp_123456789012345678901234567890123456"
	content := "token=" + secret
	match := detectors.Match{
		Detector:   "github_token",
		Value:      secret,
		Start:      len("token="),
		End:        len(content),
		Confidence: detectors.ConfidenceHigh,
	}
	key := strings.Repeat("é", MaxPublicProvenanceBytes/2)
	normalizer, err := NewDetailedNormalizer(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeConfig,
		Key:            key,
		Content:        content,
	}, []detectors.Match{match})
	if err != nil {
		t.Fatalf("NewDetailedNormalizer() error = %v", err)
	}
	finding, err := normalizer.Normalize(match)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if finding.Key != key {
		t.Fatalf("finding.Key changed an in-bound value")
	}
	if len(finding.SourceLocation) > MaxPublicProvenanceBytes {
		t.Fatalf("len(finding.SourceLocation) = %d", len(finding.SourceLocation))
	}
	if !utf8.ValidString(finding.SourceLocation) {
		t.Fatalf("finding.SourceLocation is not valid UTF-8: %q", finding.SourceLocation)
	}
	if !strings.Contains(finding.SourceLocation, "...[sha256:") {
		t.Fatalf("finding.SourceLocation = %q", finding.SourceLocation)
	}
}

func TestDetailedNormalizerHashesRedactedProvenance(t *testing.T) {
	secret := "sk-" + "or-v1-" + strings.Repeat("a", 64)
	filePath := strings.Repeat("prefix/", 80) + secret
	match := detectors.Match{
		Detector:   "openrouter_api_key",
		Value:      secret,
		Start:      len(filePath) - len(secret),
		End:        len(filePath),
		Confidence: detectors.ConfidenceHigh,
	}
	normalizer, err := NewDetailedNormalizerWithProvenance(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeFileFinal,
		FilePath:       filePath,
		Content:        "ghp_123456789012345678901234567890123456",
	}, []detectors.Match{{
		Detector:   "github_token",
		Value:      "ghp_123456789012345678901234567890123456",
		Start:      0,
		End:        40,
		Confidence: detectors.ConfidenceHigh,
	}}, []detectors.Match{match}, nil)
	if err != nil {
		t.Fatalf("NewDetailedNormalizerWithProvenance() error = %v", err)
	}

	redacted := strings.Replace(filePath, secret, "[REDACTED]", 1)
	want := boundedSanitizedProvenance(redacted)
	if normalizer.filePath != want {
		t.Fatalf("normalizer.filePath = %q, want %q", normalizer.filePath, want)
	}
	rawSuffix := provenanceDigestSuffix(filePath)
	if strings.HasSuffix(normalizer.filePath, rawSuffix) {
		t.Fatalf("normalizer.filePath contains a raw-derived suffix: %q", normalizer.filePath)
	}
}

func TestDetailedNormalizerHandlesManyMatchesWithOnePreparedIndex(t *testing.T) {
	const matchCount = 4000
	input, matches := manyMatchNormalizationFixture(matchCount)
	normalizer, err := NewDetailedNormalizer(input, matches)
	if err != nil {
		t.Fatalf("NewDetailedNormalizer() error = %v", err)
	}
	if len(normalizer.spans) != matchCount {
		t.Fatalf("len(normalizer.spans) = %d, want %d", len(normalizer.spans), matchCount)
	}
	for index, match := range matches {
		finding, err := normalizer.Normalize(match)
		if err != nil {
			t.Fatalf("Normalize(%d) error = %v", index, err)
		}
		if strings.Contains(finding.ContextSnippet, match.Value) {
			t.Fatalf("Normalize(%d) leaked raw value", index)
		}
	}
}

func BenchmarkDetailedNormalizerManyMatches(b *testing.B) {
	input, matches := manyMatchNormalizationFixture(4000)
	b.ResetTimer()
	for range b.N {
		normalizer, err := NewDetailedNormalizer(input, matches)
		if err != nil {
			b.Fatal(err)
		}
		for _, match := range matches {
			if _, err := normalizer.Normalize(match); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func manyMatchNormalizationFixture(count int) (Input, []detectors.Match) {
	value := "CCIP" + "AT_AbCdEfGhIjKlMnOpQrStUv_" + strings.Repeat("a", 40)
	var content strings.Builder
	matches := make([]detectors.Match, 0, count)
	for index := 0; index < count; index++ {
		if index > 0 {
			content.WriteByte('\n')
		}
		start := content.Len()
		content.WriteString(value)
		matches = append(matches, detectors.Match{
			Detector:   "circleci_personal_api_token",
			Value:      value,
			Start:      start,
			End:        content.Len(),
			Confidence: detectors.ConfidenceHigh,
		})
	}
	return Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeFileFinal,
		FilePath:       "app/secrets.txt",
		Content:        content.String(),
	}, matches
}

func TestDeduplicateDetailedIgnoresRawSnippetRendering(t *testing.T) {
	items := []DetailedFinding{
		testDetailedFinding("app.env", "github_token", "TOKEN=ghp_123456789012345678901234567890123456", "TOKEN=ghp********************************56"),
		testDetailedFinding("app.env", "github_token", "GH_TOKEN=ghp_123456789012345678901234567890123456", "GH_TOKEN=ghp********************************56"),
	}

	deduped := DeduplicateDetailed(items)
	if len(deduped) != 1 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}

func TestNormalizeDetailedWithMatchesRedactsAdjacentSecrets(t *testing.T) {
	firstValue := "ghp_123456789012345678901234567890123456"
	secondValue := "glpat-12345678901234567890"
	content := "github=" + firstValue + " gitlab=" + secondValue
	firstStart := strings.Index(content, firstValue)
	secondStart := strings.Index(content, secondValue)
	first := detectors.Match{Detector: "github_token", Value: firstValue, Start: firstStart, End: firstStart + len(firstValue), Confidence: detectors.ConfidenceHigh}
	second := detectors.Match{Detector: "gitlab_token", Value: secondValue, Start: secondStart, End: secondStart + len(secondValue), Confidence: detectors.ConfidenceHigh}

	finding, err := NormalizeDetailedWithMatches(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeEnv,
		Key:            "TOKENS",
		Content:        content,
	}, first, []detectors.Match{first, second})
	if err != nil {
		t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
	}
	if strings.Contains(finding.ContextSnippet, firstValue) || strings.Contains(finding.ContextSnippet, secondValue) {
		t.Fatalf("ContextSnippet leaked a secret: %q", finding.ContextSnippet)
	}
	if got := strings.Count(finding.ContextSnippet, "[REDACTED]"); got != 2 {
		t.Fatalf("redaction count = %d, snippet = %q", got, finding.ContextSnippet)
	}
}

func TestNormalizeDetailedWithMatchesRedactsOverlappingAndMultilineMatches(t *testing.T) {
	content := "préfix secret-line-one\nsecret-line-two suffix"
	value := "secret-line-one\nsecret-line-two"
	start := strings.Index(content, value)
	match := detectors.Match{Detector: "pem_private_key", Value: value, Start: start, End: start + len(value), Confidence: detectors.ConfidenceHigh}

	finding, err := NormalizeDetailedWithMatches(Input{
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceType:     SourceTypeConfig,
		Content:        content,
	}, match, []detectors.Match{match})
	if err != nil {
		t.Fatalf("NormalizeDetailedWithMatches() error = %v", err)
	}
	if !strings.Contains(finding.ContextSnippet, "[REDACTED MULTILINE]") {
		t.Fatalf("ContextSnippet = %q", finding.ContextSnippet)
	}
	if !utf8.ValidString(finding.ContextSnippet) {
		t.Fatalf("ContextSnippet is not valid UTF-8: %q", finding.ContextSnippet)
	}
	if got := Redact(value); got != "[REDACTED MULTILINE]" {
		t.Fatalf("Redact() = %q", got)
	}
}

func TestDeduplicatePreservesDistinctPublicSourceLocations(t *testing.T) {
	items := []Finding{
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			FilePath:       "z.env",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			FilePath:       "a.env",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
	}

	deduped := Deduplicate(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
	if deduped[0].FilePath != "a.env" || deduped[1].FilePath != "z.env" {
		t.Fatalf("deduped file paths = %q, %q", deduped[0].FilePath, deduped[1].FilePath)
	}
}

func TestDeduplicatePreservesDistinctContextSnippets(t *testing.T) {
	items := []Finding{
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeEnv,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			ContextSnippet: "TOKEN=ghp********************************56",
		},
		{
			DetectorName:   "github_token",
			SourceType:     SourceTypeLabel,
			ManifestDigest: "sha256:a",
			Fingerprint:    "one",
			ContextSnippet: "token=ghp********************************56",
		},
	}

	deduped := Deduplicate(items)
	if len(deduped) != 2 {
		t.Fatalf("len(deduped) = %d", len(deduped))
	}
}

func testDetailedFinding(filePath, detectorName, rawSnippet, contextSnippet string) DetailedFinding {
	return DetailedFinding{
		Finding: Finding{
			DetectorName:   detectorName,
			Confidence:     "high",
			Disposition:    DispositionActionable,
			SourceType:     SourceTypeFileFinal,
			ManifestDigest: "sha256:a",
			Platform: manifest.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			FilePath:       filePath,
			Fingerprint:    Fingerprint("ghp_123456789012345678901234567890123456"),
			ContextSnippet: contextSnippet,
		},
		Value:          "ghp_123456789012345678901234567890123456",
		RawSnippet:     rawSnippet,
		SourceLocation: "file:" + filePath,
		MatchStart:     6,
		MatchEnd:       46,
	}
}
