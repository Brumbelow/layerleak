package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("LAYERLEAK_LOG_LEVEL", "")
	t.Setenv("LAYERLEAK_API_ADDR", "")
	t.Setenv("LAYERLEAK_REGISTRY_BASE_URL", "")
	t.Setenv("LAYERLEAK_REGISTRY_AUTH_URL", "")
	t.Setenv("LAYERLEAK_REGISTRY_USERNAME", "")
	t.Setenv("LAYERLEAK_REGISTRY_PASSWORD", "")
	t.Setenv("LAYERLEAK_DOCKER_CONFIG", "")
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
	t.Setenv("LAYERLEAK_API_PRESTOP_DELAY", "")
	t.Setenv("LAYERLEAK_API_READINESS_TIMEOUT", "")
	t.Setenv("LAYERLEAK_API_READINESS_CACHE_TTL", "")
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
	if cfg.APIPreStopDelay != 0 {
		t.Fatalf("cfg.APIPreStopDelay = %s", cfg.APIPreStopDelay)
	}
	if cfg.APIReadinessCacheTTL != 5*time.Second {
		t.Fatalf("cfg.APIReadinessCacheTTL = %s", cfg.APIReadinessCacheTTL)
	}

	if cfg.RegistryBaseURL != "" {
		t.Fatalf("cfg.RegistryBaseURL = %q", cfg.RegistryBaseURL)
	}

	if cfg.RegistryAuthURL != "" {
		t.Fatalf("cfg.RegistryAuthURL = %q", cfg.RegistryAuthURL)
	}
	if cfg.RegistryUsername != "" || cfg.RegistryPassword != "" || cfg.DockerConfigPath != "" {
		t.Fatalf("registry credential defaults = (%q, set=%v, %q)", cfg.RegistryUsername, cfg.RegistryPassword != "", cfg.DockerConfigPath)
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

func TestLoadNonNegativeDurationsAllowZeroRejectNegative(t *testing.T) {
	tests := []struct {
		key  string
		read func(Config) time.Duration
	}{
		{key: "LAYERLEAK_API_PRESTOP_DELAY", read: func(cfg Config) time.Duration { return cfg.APIPreStopDelay }},
		{key: "LAYERLEAK_API_READINESS_CACHE_TTL", read: func(cfg Config) time.Duration { return cfg.APIReadinessCacheTTL }},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			t.Setenv(test.key, "0s")
			cfg, err := Load()
			if err != nil || test.read(cfg) != 0 {
				t.Fatalf("Load() with 0s = (%s, %v)", test.read(cfg), err)
			}

			t.Setenv(test.key, "7s")
			cfg, err = Load()
			if err != nil || test.read(cfg) != 7*time.Second {
				t.Fatalf("Load() with 7s = (%s, %v)", test.read(cfg), err)
			}

			for _, value := range []string{"-1s", "soon"} {
				t.Setenv(test.key, value)
				if _, err := Load(); err == nil {
					t.Fatalf("Load() with %q error = nil", value)
				}
			}
		})
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

// composeOnlyKeys are read by docker-compose.yml (or the migration command)
// rather than by config.Load.
var composeOnlyKeys = map[string]bool{
	"LAYERLEAK_IMAGE":                 true,
	"LAYERLEAK_API_HOST":              true,
	"LAYERLEAK_API_PORT":              true,
	"LAYERLEAK_API_STOP_GRACE_PERIOD": true,
	"LAYERLEAK_DB_NAME":               true,
	"LAYERLEAK_DB_USER":               true,
	"LAYERLEAK_DB_PASSWORD":           true,
	"LAYERLEAK_MIGRATIONS_DIR":        true,
}

// clearLayerleakEnv blanks every LAYERLEAK_* variable in the process plus the
// given keys so Load() observes defaults only.
func clearLayerleakEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "LAYERLEAK_") {
			t.Setenv(key, "")
		}
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func readEnvExample(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	values := make(map[string]string)
	for number, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "LAYERLEAK_") {
			t.Fatalf(".env.example line %d is not a LAYERLEAK_ assignment: %q", number+1, line)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf(".env.example defines %s twice", key)
		}
		values[key] = value
	}
	return values
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// TestEnvExampleMatchesDefaults pins .env.example to config.Load: sourcing the
// example must produce exactly the built-in defaults, and it must not ship a
// live database URL or password.
func TestEnvExampleMatchesDefaults(t *testing.T) {
	example := readEnvExample(t)
	keys := sortedKeys(example)
	clearLayerleakEnv(t, keys...)
	defaults, err := Load()
	if err != nil {
		t.Fatalf("Load() with defaults error = %v", err)
	}
	for _, key := range keys {
		if composeOnlyKeys[key] {
			continue
		}
		t.Setenv(key, example[key])
	}
	fromExample, err := Load()
	if err != nil {
		t.Fatalf("Load() from .env.example error = %v", err)
	}
	if !reflect.DeepEqual(defaults, fromExample) {
		t.Fatalf(".env.example differs from defaults:\n defaults: %+v\n example:  %+v", defaults, fromExample)
	}
	for _, key := range []string{"LAYERLEAK_DATABASE_URL", "LAYERLEAK_DB_PASSWORD", "LAYERLEAK_FINDINGS_DIR", "LAYERLEAK_MIGRATIONS_DIR"} {
		value, present := example[key]
		if !present {
			t.Fatalf(".env.example must document %s", key)
		}
		if value != "" {
			t.Fatalf(".env.example must leave %s empty, got %q", key, value)
		}
	}
}

// TestComposeDefaultsMatchConfig pins every ${VAR:-default} in
// docker-compose.yml to the built-in defaults.
func TestComposeDefaultsMatchConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	pattern := regexp.MustCompile(`(?m)^\s+(LAYERLEAK_[A-Z_]+): "?\$\{(LAYERLEAK_[A-Z_]+):-([^}]*)\}"?\s*$`)
	matches := pattern.FindAllStringSubmatch(string(raw), -1)
	if len(matches) < 30 {
		t.Fatalf("expected at least 30 defaulted compose variables, found %d", len(matches))
	}
	values := make(map[string]string)
	for _, match := range matches {
		name, reference, fallback := match[1], match[2], match[3]
		if name != reference {
			t.Fatalf("compose variable %s is populated from %s", name, reference)
		}
		if composeOnlyKeys[name] {
			continue
		}
		if previous, seen := values[name]; seen && previous != fallback {
			t.Fatalf("compose variable %s has defaults %q and %q", name, previous, fallback)
		}
		values[name] = fallback
	}
	keys := sortedKeys(values)
	clearLayerleakEnv(t, keys...)
	defaults, err := Load()
	if err != nil {
		t.Fatalf("Load() with defaults error = %v", err)
	}
	for _, key := range keys {
		t.Setenv(key, values[key])
	}
	fromCompose, err := Load()
	if err != nil {
		t.Fatalf("Load() from compose defaults error = %v", err)
	}
	if !reflect.DeepEqual(defaults, fromCompose) {
		t.Fatalf("docker-compose.yml defaults differ from config defaults:\n defaults: %+v\n compose:  %+v", defaults, fromCompose)
	}
}

func TestLoadRejectsZeroForPositiveOnlyBounds(t *testing.T) {
	keys := []string{
		"LAYERLEAK_API_MAX_REQUEST_BYTES",
		"LAYERLEAK_API_MAX_CONCURRENT_SCANS",
		"LAYERLEAK_REGISTRY_MAX_REDIRECTS",
		"LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS",
		"LAYERLEAK_MAX_AUTH_RESPONSE_BYTES",
		"LAYERLEAK_MAX_FILE_BYTES",
		"LAYERLEAK_TAG_PAGE_SIZE",
		"LAYERLEAK_DATABASE_MAX_OPEN_CONNS",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv(key, "0")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "greater than zero") {
				t.Fatalf("Load() error = %v, want %s rejection", err, key)
			}
		})
	}
}

func TestLoadValidatesAPIAddr(t *testing.T) {
	valid := []string{"0.0.0.0:8080", "[::]:8080", ":8080", "localhost:8080", "LOCALHOST:8080", "127.0.0.1:1", "api.internal.example:65535"}
	for _, value := range valid {
		t.Run("valid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_API_ADDR", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.APIAddr != value {
				t.Fatalf("cfg.APIAddr = %q, want %q", cfg.APIAddr, value)
			}
		})
	}
	invalid := []string{"8080", "localhost", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "http://127.0.0.1:8080", "bad host:8080", "::1:8080", "-bad.example:8080"}
	for _, value := range invalid {
		t.Run("invalid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_API_ADDR", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_API_ADDR") {
				t.Fatalf("Load() error = %v, want LAYERLEAK_API_ADDR rejection", err)
			}
		})
	}
}

func TestLoadAcceptsBooleanSpellings(t *testing.T) {
	cases := map[string]bool{
		"1": true, "t": true, "true": true, "TRUE": true, "True": true, "yes": true, "Yes": true, "y": true, "on": true, "ON": true,
		"0": false, "f": false, "false": false, "FALSE": false, "no": false, "n": false, "off": false, " off ": false,
	}
	for value, want := range cases {
		t.Run(value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.PersistRawSecrets != want {
				t.Fatalf("PersistRawSecrets = %v for %q, want %v", cfg.PersistRawSecrets, value, want)
			}
		})
	}
	for _, value := range []string{"maybe", "2", "enabled", "yes please"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_PERSIST_RAW_SECRETS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_PERSIST_RAW_SECRETS") {
				t.Fatalf("Load() error = %v, want rejection", err)
			}
		})
	}
}

func TestLoadRestrictsLogLevelNames(t *testing.T) {
	for value, want := range map[string]string{"DEBUG": "debug", "Info": "info", "warn": "warn", "ERROR": "error"} {
		t.Run(value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_LOG_LEVEL", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.LogLevel != want {
				t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, want)
			}
		})
	}
	for _, value := range []string{"info+2", "warn-1", "warning", "trace", "fatal"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_LOG_LEVEL", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_LOG_LEVEL") {
				t.Fatalf("Load() error = %v, want rejection", err)
			}
		})
	}
}

func TestLoadRestrictsLogFormatNames(t *testing.T) {
	clearLayerleakEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("default LogFormat = %q, want json", cfg.LogFormat)
	}
	for value, want := range map[string]string{"JSON": "json", "text": "text", " Text ": "text"} {
		t.Run(value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_LOG_FORMAT", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.LogFormat != want {
				t.Fatalf("LogFormat = %q, want %q", cfg.LogFormat, want)
			}
		})
	}
	for _, value := range []string{"logfmt", "yaml", "json,text", "pretty"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_LOG_FORMAT", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_LOG_FORMAT") {
				t.Fatalf("Load() error = %v, want rejection", err)
			}
		})
	}
}

// TestREADMEDocumentsEveryVariable keeps the README configuration tables and
// .env.example in lockstep: every variable in one must appear in the other.
func TestREADMEDocumentsEveryVariable(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	rowPattern := regexp.MustCompile("(?m)^\\| `(LAYERLEAK_[A-Z_]+)` \\|")
	documented := make(map[string]bool)
	for _, match := range rowPattern.FindAllStringSubmatch(string(readme), -1) {
		if documented[match[1]] {
			t.Fatalf("README documents %s twice", match[1])
		}
		documented[match[1]] = true
	}
	example := readEnvExample(t)
	for key := range example {
		if !documented[key] {
			t.Errorf("%s is in .env.example but has no README table row", key)
		}
	}
	for key := range documented {
		if _, present := example[key]; !present {
			t.Errorf("%s has a README table row but is missing from .env.example", key)
		}
	}
	if len(documented) < 50 {
		t.Fatalf("expected at least 50 documented variables, found %d", len(documented))
	}
}

func TestLoadValidatesRegistryEndpointOverrides(t *testing.T) {
	for _, key := range []string{"LAYERLEAK_REGISTRY_BASE_URL", "LAYERLEAK_REGISTRY_AUTH_URL"} {
		for _, value := range []string{"https://registry.internal:5000", "http://127.0.0.1:5000/v2/", "https://auth.example.com/token", "https://[::1]:5000"} {
			t.Run("valid/"+key+"/"+value, func(t *testing.T) {
				clearLayerleakEnv(t)
				t.Setenv(key, value)
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				got := cfg.RegistryBaseURL
				if key == "LAYERLEAK_REGISTRY_AUTH_URL" {
					got = cfg.RegistryAuthURL
				}
				if got != value {
					t.Fatalf("loaded %q, want %q", got, value)
				}
			})
		}
		for _, value := range []string{"registry.internal:5000", "ftp://registry.internal", "https://user:secret@registry.internal", "https://registry.internal/#frag", "https://", "https://bad host/", "https://registry.internal:70000"} {
			t.Run("invalid/"+key+"/"+value, func(t *testing.T) {
				clearLayerleakEnv(t)
				t.Setenv(key, value)
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("Load() error = %v, want %s rejection", err, key)
				}
			})
		}
	}
}

func TestLoadRegistryCredentials(t *testing.T) {
	const password = "synthetic-password-not-real-0001"
	t.Run("pair", func(t *testing.T) {
		clearLayerleakEnv(t)
		t.Setenv("LAYERLEAK_REGISTRY_USERNAME", "  scanner-bot  ")
		t.Setenv("LAYERLEAK_REGISTRY_PASSWORD", password)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.RegistryUsername != "scanner-bot" || string(cfg.RegistryPassword) != password {
			t.Fatalf("credentials = (%q, match=%v)", cfg.RegistryUsername, string(cfg.RegistryPassword) == password)
		}
	})
	t.Run("password keeps surrounding whitespace", func(t *testing.T) {
		clearLayerleakEnv(t)
		t.Setenv("LAYERLEAK_REGISTRY_USERNAME", "scanner-bot")
		t.Setenv("LAYERLEAK_REGISTRY_PASSWORD", " "+password+" ")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if string(cfg.RegistryPassword) != " "+password+" " {
			t.Fatal("password was trimmed")
		}
	})
	for name, env := range map[string]map[string]string{
		"username only":            {"LAYERLEAK_REGISTRY_USERNAME": "scanner-bot"},
		"password only":            {"LAYERLEAK_REGISTRY_PASSWORD": password},
		"blank username, password": {"LAYERLEAK_REGISTRY_USERNAME": "   ", "LAYERLEAK_REGISTRY_PASSWORD": password},
	} {
		t.Run(name, func(t *testing.T) {
			clearLayerleakEnv(t)
			for key, value := range env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "LAYERLEAK_REGISTRY_USERNAME") || !strings.Contains(err.Error(), "LAYERLEAK_REGISTRY_PASSWORD") {
				t.Fatalf("Load() error = %v, want both variable names", err)
			}
			if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "scanner-bot") {
				t.Fatalf("Load() error echoes a credential: %v", err)
			}
		})
	}
}

func TestLoadValidatesDockerConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"auths":{}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("regular file", func(t *testing.T) {
		clearLayerleakEnv(t)
		t.Setenv("LAYERLEAK_DOCKER_CONFIG", " "+path+" ")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.DockerConfigPath != path {
			t.Fatalf("DockerConfigPath = %q, want %q", cfg.DockerConfigPath, path)
		}
	})
	for name, value := range map[string]string{
		"missing file": filepath.Join(dir, "absent.json"),
		"directory":    dir,
	} {
		t.Run(name, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_DOCKER_CONFIG", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DOCKER_CONFIG") {
				t.Fatalf("Load() error = %v, want LAYERLEAK_DOCKER_CONFIG rejection", err)
			}
		})
	}
}

func TestSecretFormattingRedacts(t *testing.T) {
	const password = "synthetic-password-not-real-0001"
	cfg := Config{RegistryUsername: "scanner-bot", RegistryPassword: Secret(password)}
	for _, text := range []string{
		fmt.Sprint(cfg.RegistryPassword),
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%s %q", cfg.RegistryPassword, cfg.RegistryPassword),
	} {
		if strings.Contains(text, password) {
			t.Fatalf("formatted config reveals the password: %q", text)
		}
	}
	if string(cfg.RegistryPassword) != password {
		t.Fatal("string(Secret) must return the value")
	}
	if fmt.Sprint(Secret("")) != "<redacted>" {
		t.Fatalf("empty secret formats as %q", fmt.Sprint(Secret("")))
	}
}
