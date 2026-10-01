package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// minBearerTokenLength is the shortest accepted API token. 32 printable
	// ASCII characters carry at least 128 bits when generated randomly.
	minBearerTokenLength = 32
	// maxBearerTokenFileBytes bounds the token file read so a misconfigured
	// path (a device, a log) cannot make startup allocate without limit.
	maxBearerTokenFileBytes = 64 << 10
)

// bearerTokenDigestsFromEnv loads the optional API bearer tokens from either
// the inline comma-separated variable or the one-token-per-line file named by
// fileKey; setting both is an error. Tokens are validated (printable ASCII, at
// least 32 characters), deduplicated and returned only as SHA-256 digests in
// first-seen order, so the plaintext never outlives Load. Nil means
// authentication is disabled. Error messages name positions, never values.
func bearerTokenDigestsFromEnv(inlineKey, fileKey string) ([][]byte, error) {
	inline := strings.TrimSpace(os.Getenv(inlineKey))
	path := strings.TrimSpace(os.Getenv(fileKey))
	switch {
	case inline == "" && path == "":
		return nil, nil
	case inline != "" && path != "":
		return nil, fmt.Errorf("%s and %s must not both be set; choose one token source", inlineKey, fileKey)
	case inline != "":
		return bearerTokenDigests(inlineKey, strings.Split(inline, ","))
	}
	entries, err := readBearerTokenFile(fileKey, path)
	if err != nil {
		return nil, err
	}
	return bearerTokenDigests(fileKey, entries)
}

// readBearerTokenFile returns the non-blank lines of the token file. The read
// is bounded by maxBearerTokenFileBytes.
func readBearerTokenFile(key, path string) ([]string, error) {
	file, err := os.Open(path) //nolint:gosec // the operator names the token file on purpose
	if err != nil {
		return nil, fmt.Errorf("parse %s: open token file: %w", key, err)
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maxBearerTokenFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("parse %s: read token file: %w", key, err)
	}
	if len(body) > maxBearerTokenFileBytes {
		return nil, fmt.Errorf("parse %s: token file exceeds %d bytes", key, maxBearerTokenFileBytes)
	}
	entries := make([]string, 0)
	for _, line := range bytes.Split(body, []byte("\n")) {
		if trimmed := strings.TrimSpace(string(line)); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("parse %s: token file contains no tokens", key)
	}
	return entries, nil
}

func bearerTokenDigests(key string, entries []string) ([][]byte, error) {
	digests := make([][]byte, 0, len(entries))
	seen := make(map[[sha256.Size]byte]struct{}, len(entries))
	for index, entry := range entries {
		token := strings.TrimSpace(entry)
		if err := validateBearerToken(token); err != nil {
			return nil, fmt.Errorf("parse %s: token %d %w", key, index+1, err)
		}
		digest := sha256.Sum256([]byte(token))
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		digests = append(digests, digest[:])
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("parse %s: no tokens configured", key)
	}
	return digests, nil
}

// validateBearerToken accepts printable ASCII without spaces (the RFC 6750
// token68 alphabet and more) of at least minBearerTokenLength bytes.
func validateBearerToken(token string) error {
	if token == "" {
		return fmt.Errorf("is empty")
	}
	if len(token) < minBearerTokenLength {
		return fmt.Errorf("is shorter than %d characters", minBearerTokenLength)
	}
	for _, character := range token {
		if character <= ' ' || character > '~' {
			return fmt.Errorf("must contain only printable ASCII characters without spaces")
		}
	}
	return nil
}
