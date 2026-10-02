package findings

import (
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// DET-03: the same secret found in an image-config Env entry and in a .env
// file must yield one fingerprint, so cross-source dedup, unique_fingerprints
// and finding history line up.
func TestEnvAndFileFindingsShareFingerprint(t *testing.T) {
	const secret = "q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5"
	set := detectors.Default()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	platform := manifest.Platform{OS: "linux", Architecture: "amd64"}

	envInput := Input{ManifestDigest: digest, Platform: platform, SourceType: SourceTypeEnv, Key: "config.env.DB_PASSWORD", Content: "DB_PASSWORD=" + secret}
	envMatches := set.Scan(detectors.ScanInput{Content: envInput.Content, Key: "DB_PASSWORD"})
	fileInput := Input{ManifestDigest: digest, Platform: platform, SourceType: SourceTypeFileFinal, FilePath: "app/.env", Content: "DB_PASSWORD=" + secret + "\n"}
	fileMatches := set.Scan(detectors.ScanInput{Content: fileInput.Content, Path: fileInput.FilePath})
	if len(envMatches) != 1 || len(fileMatches) != 1 {
		t.Fatalf("env matches = %#v, file matches = %#v", envMatches, fileMatches)
	}

	envFinding, err := NormalizeDetailedWithMatches(envInput, envMatches[0], envMatches)
	if err != nil {
		t.Fatalf("Normalize(env) error = %v", err)
	}
	fileFinding, err := NormalizeDetailedWithMatches(fileInput, fileMatches[0], fileMatches)
	if err != nil {
		t.Fatalf("Normalize(file) error = %v", err)
	}

	if envFinding.Fingerprint != fileFinding.Fingerprint {
		t.Fatalf("fingerprints differ: env %q file %q", envFinding.Fingerprint, fileFinding.Fingerprint)
	}
	if envFinding.Fingerprint != Fingerprint(secret) {
		t.Fatal("fingerprint is not the sha256 of the secret alone")
	}
	if envFinding.MatchStart != len("DB_PASSWORD=") || envFinding.RedactedValue != Redact(secret) {
		t.Fatalf("env finding covers more than the value: start=%d redacted=%q", envFinding.MatchStart, envFinding.RedactedValue)
	}
	if envFinding.ContextSnippet != "DB_PASSWORD=[REDACTED]" {
		t.Fatalf("env ContextSnippet = %q", envFinding.ContextSnippet)
	}
}
