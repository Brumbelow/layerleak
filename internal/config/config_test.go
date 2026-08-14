package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("LAYERLEAK_LOG_LEVEL", "")
	t.Setenv("LAYERLEAK_API_ADDR", "")
	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "")
	t.Setenv("LAYERLEAK_REGISTRY_AUTH_URL", "")
	t.Setenv("LAYERLEAK_HTTP_TIMEOUT", "")
	t.Setenv("LAYERLEAK_SCAN_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_MAX_REQUEST_BYTES", "")
	t.Setenv("LAYERLEAK_API_SCAN_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_MAX_CONCURRENT_SCANS", "")
	t.Setenv("LAYERLEAK_API_READ_HEADER_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_READ_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_RESPONSE_WRITE_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_IDLE_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_SHUTDOWN_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_READINESS_TIMEOUT", "")
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS", "")
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS", "")
	t.Setenv("LAYERLEAK_REGISTRY_MAX_REDIRECTS", "")
	t.Setenv("LAYERLEAK_BLOB_TIMEOUT", "")
	t.Setenv("LAYERLEAK_MAX_AUTH_RESPONSE_BYTES", "")
	t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", "")
	t.Setenv("LAYERLEAK_MAX_RAW_FINDING_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_LAYER_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_LAYER_ENTRIES", "")
	t.Setenv("LAYERLEAK_MAX_IMAGE_LAYERS", "")
	t.Setenv("LAYERLEAK_MAX_IMAGE_MANIFESTS", "")
	t.Setenv("LAYERLEAK_MAX_IMAGE_LAYER_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_IMAGE_ARTIFACTS", "")
	t.Setenv("LAYERLEAK_MAX_RETAINED_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_MANIFEST_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_CONFIG_BYTES", "")
	t.Setenv("LAYERLEAK_MAX_TAG_RESPONSE_BYTES", "")
	t.Setenv("LAYERLEAK_TAG_PAGE_SIZE", "")
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TAGS", "")
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TARGETS", "")
	t.Setenv("LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS", "")
	t.Setenv("LAYERLEAK_MAX_FINDINGS_PER_SCAN", "")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", "")
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	t.Setenv("LAYERLEAK_DATABASE_MAX_OPEN_CONNS", "")
	t.Setenv("LAYERLEAK_DATABASE_MAX_IDLE_CONNS", "")
	t.Setenv("LAYERLEAK_DATABASE_CONN_MAX_LIFETIME", "")
	t.Setenv("LAYERLEAK_DATABASE_CONN_MAX_IDLE_TIME", "")
	t.Setenv("LAYERLEAK_DATABASE_QUERY_TIMEOUT", "")
	t.Setenv("LAYERLEAK_DATABASE_WRITE_TIMEOUT", "")
	t.Setenv("LAYERLEAK_MIGRATIONS_DIR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "info" {
		t.Fatalf("cfg.LogLevel = %q", cfg.LogLevel)
	}
	if cfg.APIAddr != "127.0.0.1:8080" {
		t.Fatalf("cfg.APIAddr = %q", cfg.APIAddr)
	}
	if cfg.APIMaxRequestBytes != 16*(1<<10) || cfg.APIMaxConcurrentScans != 1 {
		t.Fatalf("api limits = (%d,%d)", cfg.APIMaxRequestBytes, cfg.APIMaxConcurrentScans)
	}
	if cfg.APIScanTimeout != 30*time.Minute || cfg.APIReadHeaderTimeout != 5*time.Second || cfg.APIReadTimeout != 15*time.Second || cfg.APIResponseWriteTimeout != 30*time.Second || cfg.APIIdleTimeout != time.Minute || cfg.APIShutdownTimeout != 30*time.Second || cfg.APIReadinessTimeout != 2*time.Second {
		t.Fatalf("api timeouts = %#v", cfg)
	}

	if cfg.RegistryBaseURL != "" {
		t.Fatalf("cfg.RegistryBaseURL = %q", cfg.RegistryBaseURL)
	}

	if cfg.RegistryAuthURL != "" {
		t.Fatalf("cfg.RegistryAuthURL = %q", cfg.RegistryAuthURL)
	}

	if cfg.HTTPTimeout != 30*time.Second {
		t.Fatalf("cfg.HTTPTimeout = %s", cfg.HTTPTimeout)
	}
	if cfg.ScanTimeout != 30*time.Minute || cfg.BlobTimeout != 10*time.Minute {
		t.Fatalf("scan/blob timeouts = (%s,%s)", cfg.ScanTimeout, cfg.BlobTimeout)
	}
	if len(cfg.AllowedPrivateRegistryHosts) != 0 || len(cfg.AllowedPrivateAuthHosts) != 0 || cfg.RegistryMaxRedirects != 3 || cfg.MaxAuthResponseBytes != 1<<20 {
		t.Fatalf("registry hardening defaults = %#v", cfg)
	}
	if cfg.PersistRawSecrets {
		t.Fatal("cfg.PersistRawSecrets = true")
	}
	if cfg.MaxRawFindingBytes != 64*(1<<20) {
		t.Fatalf("cfg.MaxRawFindingBytes = %d", cfg.MaxRawFindingBytes)
	}

	if cfg.MaxFileBytes != 1<<20 {
		t.Fatalf("cfg.MaxFileBytes = %d", cfg.MaxFileBytes)
	}
	if cfg.MaxLayerBytes != 512*(1<<20) {
		t.Fatalf("cfg.MaxLayerBytes = %d", cfg.MaxLayerBytes)
	}
	if cfg.MaxLayerEntries != 50000 {
		t.Fatalf("cfg.MaxLayerEntries = %d", cfg.MaxLayerEntries)
	}
	if cfg.MaxImageLayers != 512 || cfg.MaxImageManifests != 64 || cfg.MaxImageLayerBytes != 4*(1<<30) || cfg.MaxImageArtifacts != 250000 || cfg.MaxRetainedBytes != 1<<30 {
		t.Fatalf("image limits = (%d,%d,%d,%d,%d)", cfg.MaxImageLayers, cfg.MaxImageManifests, cfg.MaxImageLayerBytes, cfg.MaxImageArtifacts, cfg.MaxRetainedBytes)
	}
	if cfg.MaxManifestBytes != 8*(1<<20) {
		t.Fatalf("cfg.MaxManifestBytes = %d", cfg.MaxManifestBytes)
	}
	if cfg.MaxConfigBytes != 8*(1<<20) {
		t.Fatalf("cfg.MaxConfigBytes = %d", cfg.MaxConfigBytes)
	}
	if cfg.MaxTagResponseBytes != 8*(1<<20) {
		t.Fatalf("cfg.MaxTagResponseBytes = %d", cfg.MaxTagResponseBytes)
	}
	if cfg.TagPageSize != 100 {
		t.Fatalf("cfg.TagPageSize = %d", cfg.TagPageSize)
	}
	if cfg.MaxRepositoryTags != 1000 {
		t.Fatalf("cfg.MaxRepositoryTags = %d", cfg.MaxRepositoryTags)
	}
	if cfg.MaxRepositoryTargets != 250 {
		t.Fatalf("cfg.MaxRepositoryTargets = %d", cfg.MaxRepositoryTargets)
	}
	if cfg.RegistryRequestAttempts != 2 {
		t.Fatalf("cfg.RegistryRequestAttempts = %d", cfg.RegistryRequestAttempts)
	}
	if cfg.MaxFindingsPerScan != 10000 {
		t.Fatalf("cfg.MaxFindingsPerScan = %d", cfg.MaxFindingsPerScan)
	}

	if cfg.FindingsDir != "" {
		t.Fatalf("cfg.FindingsDir = %q", cfg.FindingsDir)
	}
	if cfg.DatabaseMaxOpenConns != 10 || cfg.DatabaseMaxIdleConns != 5 || cfg.DatabaseConnMaxLifetime != 30*time.Minute || cfg.DatabaseConnMaxIdleTime != 5*time.Minute || cfg.DatabaseQueryTimeout != 10*time.Second || cfg.DatabaseWriteTimeout != 2*time.Minute {
		t.Fatalf("database defaults = %#v", cfg)
	}
	if cfg.MigrationsDir != "/app/migrations" {
		t.Fatalf("cfg.MigrationsDir = %q", cfg.MigrationsDir)
	}
}

func TestLoadInvalidTimeout(t *testing.T) {
	t.Setenv("LAYERLEAK_HTTP_TIMEOUT", "not-a-duration")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadRejectsNonPositiveTimeout(t *testing.T) {
	t.Setenv("LAYERLEAK_SCAN_TIMEOUT", "0s")

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

func TestLoadInvalidMaxLayerBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_LAYER_BYTES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxLayerEntries(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_LAYER_ENTRIES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxManifestBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_MANIFEST_BYTES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxConfigBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_CONFIG_BYTES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxRawFindingBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_RAW_FINDING_BYTES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadAllowsPersistRawSecretsOptIn(t *testing.T) {
	t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.PersistRawSecrets {
		t.Fatal("cfg.PersistRawSecrets = false")
	}
}

func TestLoadInvalidPersistRawSecrets(t *testing.T) {
	t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", "maybe")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxTagResponseBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_TAG_RESPONSE_BYTES", "-1")

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

func TestLoadAllowsZeroResourceLimits(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_LAYER_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_LAYER_ENTRIES", "0")
	t.Setenv("LAYERLEAK_MAX_IMAGE_LAYERS", "0")
	t.Setenv("LAYERLEAK_MAX_IMAGE_MANIFESTS", "0")
	t.Setenv("LAYERLEAK_MAX_IMAGE_LAYER_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_IMAGE_ARTIFACTS", "0")
	t.Setenv("LAYERLEAK_MAX_RETAINED_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TAGS", "0")
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TARGETS", "0")
	t.Setenv("LAYERLEAK_MAX_MANIFEST_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_CONFIG_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_TAG_RESPONSE_BYTES", "0")
	t.Setenv("LAYERLEAK_MAX_FINDINGS_PER_SCAN", "0")
	t.Setenv("LAYERLEAK_MAX_RAW_FINDING_BYTES", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MaxLayerBytes != 0 || cfg.MaxLayerEntries != 0 || cfg.MaxImageLayers != 0 || cfg.MaxImageManifests != 0 || cfg.MaxImageLayerBytes != 0 || cfg.MaxImageArtifacts != 0 || cfg.MaxRetainedBytes != 0 || cfg.MaxRepositoryTags != 0 || cfg.MaxRepositoryTargets != 0 || cfg.MaxManifestBytes != 0 || cfg.MaxConfigBytes != 0 || cfg.MaxTagResponseBytes != 0 || cfg.MaxFindingsPerScan != 0 || cfg.MaxRawFindingBytes != 0 {
		t.Fatalf("cfg = %#v", cfg)
	}
}

func TestLoadInvalidMaxRepositoryTags(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TAGS", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidMaxRepositoryTargets(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_REPOSITORY_TARGETS", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadInvalidRegistryRequestAttempts(t *testing.T) {
	t.Setenv("LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS", "0")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadRejectsNonPositiveRegistryMaxRedirects(t *testing.T) {
	t.Setenv("LAYERLEAK_REGISTRY_MAX_REDIRECTS", "0")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadRejectsNonNumericMaxFileBytes(t *testing.T) {
	t.Setenv("LAYERLEAK_MAX_FILE_BYTES", "abc")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestLoadTrimsFindingsDirAndDatabaseURL(t *testing.T) {
	t.Setenv("LAYERLEAK_FINDINGS_DIR", "  /tmp/findings  ")
	t.Setenv("LAYERLEAK_DATABASE_URL", "  postgres://localhost/db  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.FindingsDir != "/tmp/findings" {
		t.Fatalf("cfg.FindingsDir = %q", cfg.FindingsDir)
	}
	if cfg.DatabaseURL != "postgres://localhost/db" {
		t.Fatalf("cfg.DatabaseURL = %q", cfg.DatabaseURL)
	}
}

func TestLoadOverridesLogLevelAndAPIAddr(t *testing.T) {
	t.Setenv("LAYERLEAK_LOG_LEVEL", "debug")
	t.Setenv("LAYERLEAK_API_ADDR", "0.0.0.0:9090")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("cfg.LogLevel = %q", cfg.LogLevel)
	}
	if cfg.APIAddr != "0.0.0.0:9090" {
		t.Fatalf("cfg.APIAddr = %q", cfg.APIAddr)
	}
}

func TestLoadRejectsInvalidLogLevel(t *testing.T) {
	t.Setenv("LAYERLEAK_LOG_LEVEL", "verbose")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_LOG_LEVEL") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadParsesPrivateHostAllowlists(t *testing.T) {
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS", " Registry.Internal:5000,localhost,registry.internal:5000 ")
	t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS", "[fd00::1]:8443")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.AllowedPrivateRegistryHosts) != 2 || cfg.AllowedPrivateRegistryHosts[0] != "localhost" || cfg.AllowedPrivateRegistryHosts[1] != "registry.internal:5000" {
		t.Fatalf("cfg.AllowedPrivateRegistryHosts = %#v", cfg.AllowedPrivateRegistryHosts)
	}
	if len(cfg.AllowedPrivateAuthHosts) != 1 || cfg.AllowedPrivateAuthHosts[0] != "[fd00::1]:8443" {
		t.Fatalf("cfg.AllowedPrivateAuthHosts = %#v", cfg.AllowedPrivateAuthHosts)
	}
}

func TestLoadRejectsInvalidPrivateHostAllowlist(t *testing.T) {
	tests := []string{
		"https://registry.internal",
		"bad_host",
		"two words.internal",
		"bad..internal",
		"-bad.internal",
		"bad-.internal",
		"bad_host:5000",
		"fd00::1",
		"registry.internal:0",
		"registry.internal:65536",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS", value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil")
			}
		})
	}
}

func TestLoadRejectsIdleConnectionsAboveOpenConnections(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_MAX_OPEN_CONNS", "2")
	t.Setenv("LAYERLEAK_DATABASE_MAX_IDLE_CONNS", "3")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil")
	}
}
