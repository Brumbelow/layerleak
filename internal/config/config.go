package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel                    string
	APIAddr                     string
	APIMaxRequestBytes          int64
	APIScanTimeout              time.Duration
	APIMaxConcurrentScans       int
	APIReadHeaderTimeout        time.Duration
	APIReadTimeout              time.Duration
	APIResponseWriteTimeout     time.Duration
	APIIdleTimeout              time.Duration
	APIShutdownTimeout          time.Duration
	APIReadinessTimeout         time.Duration
	RegistryBaseURL             string
	RegistryAuthURL             string
	AllowedPrivateRegistryHosts []string
	AllowedPrivateAuthHosts     []string
	RegistryMaxRedirects        int
	BlobTimeout                 time.Duration
	MaxAuthResponseBytes        int64
	HTTPTimeout                 time.Duration
	ScanTimeout                 time.Duration
	PersistRawSecrets           bool
	MaxRawFindingBytes          int64
	MaxFileBytes                int64
	MaxLayerBytes               int64
	MaxLayerEntries             int
	MaxImageLayers              int
	MaxImageManifests           int
	MaxImageLayerBytes          int64
	MaxImageArtifacts           int
	MaxRetainedBytes            int64
	MaxManifestBytes            int64
	MaxConfigBytes              int64
	MaxTagResponseBytes         int64
	TagPageSize                 int
	MaxRepositoryTags           int
	MaxRepositoryTargets        int
	RegistryRequestAttempts     int
	MaxFindingsPerScan          int
	FindingsDir                 string
	DatabaseURL                 string
	DatabaseMaxOpenConns        int
	DatabaseMaxIdleConns        int
	DatabaseConnMaxLifetime     time.Duration
	DatabaseConnMaxIdleTime     time.Duration
	DatabaseQueryTimeout        time.Duration
	DatabaseWriteTimeout        time.Duration
	MigrationsDir               string
}

func Load() (Config, error) {
	logLevel, err := logLevelFromEnv("LAYERLEAK_LOG_LEVEL", "info")
	if err != nil {
		return Config{}, err
	}
	apiMaxRequestBytes, err := int64FromEnv("LAYERLEAK_API_MAX_REQUEST_BYTES", 16*(1<<10))
	if err != nil {
		return Config{}, err
	}
	apiScanTimeout, err := durationFromEnv("LAYERLEAK_API_SCAN_TIMEOUT", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	apiMaxConcurrentScans, err := intFromEnv("LAYERLEAK_API_MAX_CONCURRENT_SCANS", 1)
	if err != nil {
		return Config{}, err
	}
	apiReadHeaderTimeout, err := durationFromEnv("LAYERLEAK_API_READ_HEADER_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiReadTimeout, err := durationFromEnv("LAYERLEAK_API_READ_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiResponseWriteTimeout, err := durationFromEnv("LAYERLEAK_API_RESPONSE_WRITE_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiIdleTimeout, err := durationFromEnv("LAYERLEAK_API_IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiShutdownTimeout, err := durationFromEnv("LAYERLEAK_API_SHUTDOWN_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiReadinessTimeout, err := durationFromEnv("LAYERLEAK_API_READINESS_TIMEOUT", 2*time.Second)
	if err != nil {
		return Config{}, err
	}
	timeout, err := durationFromEnv("LAYERLEAK_HTTP_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	scanTimeout, err := durationFromEnv("LAYERLEAK_SCAN_TIMEOUT", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	blobTimeout, err := durationFromEnv("LAYERLEAK_BLOB_TIMEOUT", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	allowedPrivateRegistryHosts, err := hostListFromEnv("LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS")
	if err != nil {
		return Config{}, err
	}
	allowedPrivateAuthHosts, err := hostListFromEnv("LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS")
	if err != nil {
		return Config{}, err
	}
	registryMaxRedirects, err := intFromEnv("LAYERLEAK_REGISTRY_MAX_REDIRECTS", 3)
	if err != nil {
		return Config{}, err
	}
	maxAuthResponseBytes, err := int64FromEnv("LAYERLEAK_MAX_AUTH_RESPONSE_BYTES", 1<<20)
	if err != nil {
		return Config{}, err
	}
	maxFileBytes, err := int64FromEnv("LAYERLEAK_MAX_FILE_BYTES", 1<<20)
	if err != nil {
		return Config{}, err
	}
	maxLayerBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_LAYER_BYTES", 512*(1<<20))
	if err != nil {
		return Config{}, err
	}
	maxLayerEntries, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_LAYER_ENTRIES", 50000)
	if err != nil {
		return Config{}, err
	}
	maxImageLayers, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_IMAGE_LAYERS", 512)
	if err != nil {
		return Config{}, err
	}
	maxImageManifests, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_IMAGE_MANIFESTS", 64)
	if err != nil {
		return Config{}, err
	}
	maxImageLayerBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_IMAGE_LAYER_BYTES", 4*(1<<30))
	if err != nil {
		return Config{}, err
	}
	maxImageArtifacts, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_IMAGE_ARTIFACTS", 250000)
	if err != nil {
		return Config{}, err
	}
	maxRetainedBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_RETAINED_BYTES", 1<<30)
	if err != nil {
		return Config{}, err
	}
	maxManifestBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_MANIFEST_BYTES", 8*(1<<20))
	if err != nil {
		return Config{}, err
	}
	maxConfigBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_CONFIG_BYTES", 8*(1<<20))
	if err != nil {
		return Config{}, err
	}
	maxTagResponseBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_TAG_RESPONSE_BYTES", 8*(1<<20))
	if err != nil {
		return Config{}, err
	}
	tagPageSize, err := intFromEnv("LAYERLEAK_TAG_PAGE_SIZE", 100)
	if err != nil {
		return Config{}, err
	}
	maxRepositoryTags, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_REPOSITORY_TAGS", 1000)
	if err != nil {
		return Config{}, err
	}
	maxRepositoryTargets, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_REPOSITORY_TARGETS", 250)
	if err != nil {
		return Config{}, err
	}
	registryRequestAttempts, err := intFromEnv("LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS", 2)
	if err != nil {
		return Config{}, err
	}
	persistRawSecrets, err := boolFromEnv("LAYERLEAK_PERSIST_RAW_SECRETS", false)
	if err != nil {
		return Config{}, err
	}
	maxRawFindingBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_RAW_FINDING_BYTES", 64*(1<<20))
	if err != nil {
		return Config{}, err
	}
	maxFindingsPerScan, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_FINDINGS_PER_SCAN", 10000)
	if err != nil {
		return Config{}, err
	}
	databaseMaxOpenConns, err := intFromEnv("LAYERLEAK_DATABASE_MAX_OPEN_CONNS", 10)
	if err != nil {
		return Config{}, err
	}
	databaseMaxIdleConns, err := nonNegativeIntFromEnv("LAYERLEAK_DATABASE_MAX_IDLE_CONNS", 5)
	if err != nil {
		return Config{}, err
	}
	if databaseMaxIdleConns > databaseMaxOpenConns {
		return Config{}, fmt.Errorf("LAYERLEAK_DATABASE_MAX_IDLE_CONNS must be less than or equal to LAYERLEAK_DATABASE_MAX_OPEN_CONNS")
	}
	databaseConnMaxLifetime, err := durationFromEnv("LAYERLEAK_DATABASE_CONN_MAX_LIFETIME", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	databaseConnMaxIdleTime, err := durationFromEnv("LAYERLEAK_DATABASE_CONN_MAX_IDLE_TIME", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	databaseQueryTimeout, err := durationFromEnv("LAYERLEAK_DATABASE_QUERY_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	databaseWriteTimeout, err := durationFromEnv("LAYERLEAK_DATABASE_WRITE_TIMEOUT", 2*time.Minute)
	if err != nil {
		return Config{}, err
	}

	return Config{
		LogLevel:                    logLevel,
		APIAddr:                     envOrDefault("LAYERLEAK_API_ADDR", "127.0.0.1:8080"),
		APIMaxRequestBytes:          apiMaxRequestBytes,
		APIScanTimeout:              apiScanTimeout,
		APIMaxConcurrentScans:       apiMaxConcurrentScans,
		APIReadHeaderTimeout:        apiReadHeaderTimeout,
		APIReadTimeout:              apiReadTimeout,
		APIResponseWriteTimeout:     apiResponseWriteTimeout,
		APIIdleTimeout:              apiIdleTimeout,
		APIShutdownTimeout:          apiShutdownTimeout,
		APIReadinessTimeout:         apiReadinessTimeout,
		RegistryBaseURL:             envOrDefault("LAYERLEAK_REGISTRY_BASE_URL", ""),
		RegistryAuthURL:             envOrDefault("LAYERLEAK_REGISTRY_AUTH_URL", ""),
		AllowedPrivateRegistryHosts: allowedPrivateRegistryHosts,
		AllowedPrivateAuthHosts:     allowedPrivateAuthHosts,
		RegistryMaxRedirects:        registryMaxRedirects,
		BlobTimeout:                 blobTimeout,
		MaxAuthResponseBytes:        maxAuthResponseBytes,
		HTTPTimeout:                 timeout,
		ScanTimeout:                 scanTimeout,
		PersistRawSecrets:           persistRawSecrets,
		MaxRawFindingBytes:          maxRawFindingBytes,
		MaxFileBytes:                maxFileBytes,
		MaxLayerBytes:               maxLayerBytes,
		MaxLayerEntries:             maxLayerEntries,
		MaxImageLayers:              maxImageLayers,
		MaxImageManifests:           maxImageManifests,
		MaxImageLayerBytes:          maxImageLayerBytes,
		MaxImageArtifacts:           maxImageArtifacts,
		MaxRetainedBytes:            maxRetainedBytes,
		MaxManifestBytes:            maxManifestBytes,
		MaxConfigBytes:              maxConfigBytes,
		MaxTagResponseBytes:         maxTagResponseBytes,
		TagPageSize:                 tagPageSize,
		MaxRepositoryTags:           maxRepositoryTags,
		MaxRepositoryTargets:        maxRepositoryTargets,
		RegistryRequestAttempts:     registryRequestAttempts,
		MaxFindingsPerScan:          maxFindingsPerScan,
		FindingsDir:                 strings.TrimSpace(os.Getenv("LAYERLEAK_FINDINGS_DIR")),
		DatabaseURL:                 strings.TrimSpace(os.Getenv("LAYERLEAK_DATABASE_URL")),
		DatabaseMaxOpenConns:        databaseMaxOpenConns,
		DatabaseMaxIdleConns:        databaseMaxIdleConns,
		DatabaseConnMaxLifetime:     databaseConnMaxLifetime,
		DatabaseConnMaxIdleTime:     databaseConnMaxIdleTime,
		DatabaseQueryTimeout:        databaseQueryTimeout,
		DatabaseWriteTimeout:        databaseWriteTimeout,
		MigrationsDir:               envOrDefault("LAYERLEAK_MIGRATIONS_DIR", "/app/migrations"),
	}, nil
}

func logLevelFromEnv(key, fallback string) (string, error) {
	value := strings.ToLower(envOrDefault(key, fallback))
	var level slog.Level
	if err := level.UnmarshalText([]byte(value)); err != nil {
		return "", fmt.Errorf("parse %s: %w", key, err)
	}
	return value, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}

	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}

	return parsed, nil
}

func hostListFromEnv(key string) ([]string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return []string{}, nil
	}

	seen := make(map[string]struct{})
	hosts := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		host, err := normalizeAllowedHost(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", key, err)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts, nil
}

func normalizeAllowedHost(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", fmt.Errorf("host entry must not be empty")
	}
	if strings.ContainsAny(value, "/@*?#") || strings.Contains(value, "://") {
		return "", fmt.Errorf("host entry %q must be a host or host:port", raw)
	}

	if strings.HasPrefix(value, "[") {
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", fmt.Errorf("host entry %q is invalid: %w", raw, err)
		}
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("host entry %q has an invalid IP address", raw)
		}
		if err := validatePort(port); err != nil {
			return "", fmt.Errorf("host entry %q: %w", raw, err)
		}
		return net.JoinHostPort(host, port), nil
	}

	if strings.Count(value, ":") == 1 {
		host, port, err := net.SplitHostPort(value)
		if err != nil || strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("host entry %q is invalid", raw)
		}
		if err := validateHostname(host); err != nil {
			return "", fmt.Errorf("host entry %q is invalid: %w", raw, err)
		}
		if err := validatePort(port); err != nil {
			return "", fmt.Errorf("host entry %q: %w", raw, err)
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("host entry %q must bracket an IPv6 address", raw)
	}
	if err := validateHostname(value); err != nil {
		return "", fmt.Errorf("host entry %q is invalid: %w", raw, err)
	}
	return value, nil
}

func validateHostname(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname exceeds 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("hostname labels must not be empty")
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label exceeds 63 characters")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("hostname labels must not start or end with a hyphen")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("hostname contains an invalid character")
			}
		}
	}
	return nil
}

func validatePort(raw string) error {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func boolFromEnv(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}

	return parsed, nil
}

func int64FromEnv(key string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}

	return parsed, nil
}

func intFromEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}

	return parsed, nil
}

func nonNegativeInt64FromEnv(key string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be greater than or equal to zero", key)
	}

	return parsed, nil
}

func nonNegativeIntFromEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be greater than or equal to zero", key)
	}

	return parsed, nil
}
