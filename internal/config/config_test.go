package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("LAYERLEAK_LOG_LEVEL", "")
	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "")
	t.Setenv("LAYERLEAK_REGISTRY_AUTH_URL", "")
	t.Setenv("LAYERLEAK_HTTP_TIMEOUT", "")
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "")
	t.Setenv("LAYERLEAK_TAG_PAGE_SIZE", "")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", "")
	t.Setenv("LAYERLEAK_DATABASE_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "info" {
		t.Fatalf("cfg.LogLevel = %q", cfg.LogLevel)
	}

	if cfg.RegistryBaseURL != "https://registry-1.docker.io" {
		t.Fatalf("cfg.RegistryBaseURL = %q", cfg.RegistryBaseURL)
	}

	if cfg.RegistryAuthURL != "https://auth.docker.io/token" {
		t.Fatalf("cfg.RegistryAuthURL = %q", cfg.RegistryAuthURL)
	}

	if cfg.HTTPTimeout != 30*time.Second {
		t.Fatalf("cfg.HTTPTimeout = %s", cfg.HTTPTimeout)
	}

	if cfg.MaxFileBytes != 1<<20 {
		t.Fatalf("cfg.MaxFileBytes = %d", cfg.MaxFileBytes)
	}
	if cfg.TagPageSize != 100 {
		t.Fatalf("cfg.TagPageSize = %d", cfg.TagPageSize)
	}

	if cfg.FindingsDir != "" {
		t.Fatalf("cfg.FindingsDir = %q", cfg.FindingsDir)
	}
}

func TestLoadInvalidTimeout(t *testing.T) {
	t.Setenv("LAYERLEAK_HTTP_TIMEOUT", "not-a-duration")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxFileBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "0")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidTagPageSize(t *testing.T) {
	t.Setenv("LAYERLEAK_TAG_PAGE_SIZE", "0")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}
