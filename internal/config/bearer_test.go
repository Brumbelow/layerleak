package config

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Synthetic tokens: repeated characters, at least 32 bytes, never real.
const (
	testTokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testTokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func digestOf(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func TestLoadBearerTokensDisabledByDefault(t *testing.T) {
	clearLayerleakEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIBearerTokenDigests != nil {
		t.Fatalf("APIBearerTokenDigests = %v, want nil", cfg.APIBearerTokenDigests)
	}
}

func TestLoadBearerTokensFromEnvironment(t *testing.T) {
	clearLayerleakEnv(t)
	t.Setenv("LAYERLEAK_API_BEARER_TOKENS", " "+testTokenA+" , "+testTokenB+","+testTokenA)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := [][]byte{digestOf(testTokenA), digestOf(testTokenB)}
	if !reflect.DeepEqual(cfg.APIBearerTokenDigests, want) {
		t.Fatalf("APIBearerTokenDigests = %x, want %x (trimmed, deduplicated, hashed)", cfg.APIBearerTokenDigests, want)
	}
}

func TestLoadBearerTokensFromFile(t *testing.T) {
	clearLayerleakEnv(t)
	path := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(path, []byte("\n"+testTokenA+"\r\n\n  "+testTokenB+"  \n"), 0o600); err != nil {
		t.Fatalf("write tokens file: %v", err)
	}
	t.Setenv("LAYERLEAK_API_BEARER_TOKENS_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := [][]byte{digestOf(testTokenA), digestOf(testTokenB)}
	if !reflect.DeepEqual(cfg.APIBearerTokenDigests, want) {
		t.Fatalf("APIBearerTokenDigests = %x, want %x", cfg.APIBearerTokenDigests, want)
	}
}

func TestLoadBearerTokensRejectsInvalidConfigurations(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write empty tokens file: %v", err)
	}
	oversized := filepath.Join(t.TempDir(), "oversized")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("c", maxBearerTokenFileBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized tokens file: %v", err)
	}
	shortToken := "cccccccccccccccccccccccccccccc" // 30 bytes
	tests := []struct {
		name  string
		env   map[string]string
		wants []string
	}{
		{
			name:  "both sources set",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS": testTokenA, "LAYERLEAK_API_BEARER_TOKENS_FILE": emptyFile},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS", "LAYERLEAK_API_BEARER_TOKENS_FILE"},
		},
		{
			name:  "short token",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS": testTokenA + "," + shortToken},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS", "token 2", "32"},
		},
		{
			name:  "empty entry",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS": testTokenA + ",,"},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS", "token 2"},
		},
		{
			name:  "token with whitespace inside",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS": "dddddddddddddddd dddddddddddddddddddd"},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS", "token 1"},
		},
		{
			name:  "token with non ascii",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS": strings.Repeat("é", 40)},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS", "token 1"},
		},
		{
			name:  "missing file",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS_FILE": filepath.Join(t.TempDir(), "absent")},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS_FILE"},
		},
		{
			name:  "file without tokens",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS_FILE": emptyFile},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS_FILE", "no tokens"},
		},
		{
			name:  "file too large",
			env:   map[string]string{"LAYERLEAK_API_BEARER_TOKENS_FILE": oversized},
			wants: []string{"LAYERLEAK_API_BEARER_TOKENS_FILE", "exceeds"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearLayerleakEnv(t)
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil {
				t.Fatal("Load() error = nil")
			}
			for _, want := range test.wants {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Load() error = %q, want it to mention %q", err, want)
				}
			}
			if value := test.env["LAYERLEAK_API_BEARER_TOKENS"]; value != "" && strings.Contains(err.Error(), value) {
				t.Fatalf("Load() error echoes a token value: %q", err)
			}
			if strings.Contains(err.Error(), shortToken) {
				t.Fatalf("Load() error echoes the token: %q", err)
			}
		})
	}
}
