package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Secret is a configuration value that must not be printed. Its String and
// GoString methods redact it, so formatting a Config with %v, %+v or %#v (for
// example in a test failure or a debug log) never reveals it. Convert with
// string(secret) at the single point of use.
type Secret string

// String redacts the secret.
func (Secret) String() string {
	return "<redacted>"
}

// GoString redacts the secret for %#v.
func (s Secret) GoString() string {
	return s.String()
}

type Config struct {
	LogLevel string
	// LogFormat is the stderr log encoding shared by the CLI and the API:
	// "json" (default) or "text"; see internal/logging.
	LogFormat               string
	APIAddr                 string
	APIMaxRequestBytes      int64
	APIScanTimeout          time.Duration
	APIMaxConcurrentScans   int
	APIReadHeaderTimeout    time.Duration
	APIReadTimeout          time.Duration
	APIResponseWriteTimeout time.Duration
	APIIdleTimeout          time.Duration
	APIShutdownTimeout      time.Duration
	APIPreStopDelay         time.Duration
	APIReadinessTimeout     time.Duration
	APIReadinessCacheTTL    time.Duration
	// APIBearerTokenDigests holds the SHA-256 digest of every accepted API
	// bearer token (LAYERLEAK_API_BEARER_TOKENS or _FILE). Nil disables
	// authentication; the plaintext tokens are never retained.
	APIBearerTokenDigests [][]byte
	// APIMetricsAddr is the optional host:port of the Prometheus /metrics
	// listener (LAYERLEAK_API_METRICS_ADDR). Empty disables it.
	APIMetricsAddr              string
	RegistryBaseURL             string
	RegistryAuthURL             string
	RegistryUsername            string
	RegistryPassword            Secret
	DockerConfigPath            string
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
	// MaxNestedArchiveBytes bounds an archive stored in a layer (zip family,
	// gzip, tar) that is expanded one level deep: both its stored size and the
	// decompressed bytes read out of it. 0 disables nested expansion.
	MaxNestedArchiveBytes int64
	// MaxNestedArchiveEntries bounds the entries examined per nested archive;
	// 0 disables this bound (the layer and image entry budgets still apply).
	MaxNestedArchiveEntries int
	// MaxLayerCacheBytes bounds the per-sweep layer cache that lets --all-tags
	// skip re-fetching layers shared between tags. 0 (the default) disables it.
	MaxLayerCacheBytes      int64
	MaxManifestBytes        int64
	MaxConfigBytes          int64
	MaxTagResponseBytes     int64
	TagPageSize             int
	MaxRepositoryTags       int
	MaxRepositoryTargets    int
	RegistryRequestAttempts int
	MaxFindingsPerScan      int
	FindingsDir             string
	DatabaseURL             string
	DatabaseMaxOpenConns    int
	DatabaseMaxIdleConns    int
	DatabaseConnMaxLifetime time.Duration
	DatabaseConnMaxIdleTime time.Duration
	DatabaseQueryTimeout    time.Duration
	DatabaseWriteTimeout    time.Duration
}

func Load() (Config, error) {
	logLevel, err := logLevelFromEnv("LAYERLEAK_LOG_LEVEL", "info")
	if err != nil {
		return Config{}, err
	}
	logFormat, err := logFormatFromEnv("LAYERLEAK_LOG_FORMAT", "json")
	if err != nil {
		return Config{}, err
	}
	apiAddr, err := listenAddrFromEnv("LAYERLEAK_API_ADDR", "127.0.0.1:8080")
	if err != nil {
		return Config{}, err
	}
	registryBaseURL, err := endpointURLFromEnv("LAYERLEAK_REGISTRY_BASE_URL")
	if err != nil {
		return Config{}, err
	}
	registryAuthURL, err := endpointURLFromEnv("LAYERLEAK_REGISTRY_AUTH_URL")
	if err != nil {
		return Config{}, err
	}
	registryUsername, registryPassword, err := registryCredentialsFromEnv("LAYERLEAK_REGISTRY_USERNAME", "LAYERLEAK_REGISTRY_PASSWORD")
	if err != nil {
		return Config{}, err
	}
	dockerConfigPath, err := regularFilePathFromEnv("LAYERLEAK_DOCKER_CONFIG")
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
	apiPreStopDelay, err := nonNegativeDurationFromEnv("LAYERLEAK_API_PRESTOP_DELAY", 0)
	if err != nil {
		return Config{}, err
	}
	apiReadinessTimeout, err := durationFromEnv("LAYERLEAK_API_READINESS_TIMEOUT", 2*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiReadinessCacheTTL, err := nonNegativeDurationFromEnv("LAYERLEAK_API_READINESS_CACHE_TTL", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	apiBearerTokenDigests, err := bearerTokenDigestsFromEnv("LAYERLEAK_API_BEARER_TOKENS", "LAYERLEAK_API_BEARER_TOKENS_FILE")
	if err != nil {
		return Config{}, err
	}
	apiMetricsAddr, err := optionalListenAddrFromEnv("LAYERLEAK_API_METRICS_ADDR")
	if err != nil {
		return Config{}, err
	}
	if apiMetricsAddr != "" && apiMetricsAddr == apiAddr {
		return Config{}, fmt.Errorf("LAYERLEAK_API_METRICS_ADDR must differ from LAYERLEAK_API_ADDR; metrics are never served on the API port")
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
	maxNestedArchiveBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_NESTED_ARCHIVE_BYTES", 64*(1<<20))
	if err != nil {
		return Config{}, err
	}
	maxNestedArchiveEntries, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_NESTED_ARCHIVE_ENTRIES", 10000)
	if err != nil {
		return Config{}, err
	}
	maxLayerCacheBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_LAYER_CACHE_BYTES", 0)
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
		LogFormat:                   logFormat,
		APIAddr:                     apiAddr,
		APIMaxRequestBytes:          apiMaxRequestBytes,
		APIScanTimeout:              apiScanTimeout,
		APIMaxConcurrentScans:       apiMaxConcurrentScans,
		APIReadHeaderTimeout:        apiReadHeaderTimeout,
		APIReadTimeout:              apiReadTimeout,
		APIResponseWriteTimeout:     apiResponseWriteTimeout,
		APIIdleTimeout:              apiIdleTimeout,
		APIShutdownTimeout:          apiShutdownTimeout,
		APIPreStopDelay:             apiPreStopDelay,
		APIReadinessTimeout:         apiReadinessTimeout,
		APIReadinessCacheTTL:        apiReadinessCacheTTL,
		APIBearerTokenDigests:       apiBearerTokenDigests,
		APIMetricsAddr:              apiMetricsAddr,
		RegistryBaseURL:             registryBaseURL,
		RegistryAuthURL:             registryAuthURL,
		RegistryUsername:            registryUsername,
		RegistryPassword:            registryPassword,
		DockerConfigPath:            dockerConfigPath,
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
		MaxNestedArchiveBytes:       maxNestedArchiveBytes,
		MaxNestedArchiveEntries:     maxNestedArchiveEntries,
		MaxLayerCacheBytes:          maxLayerCacheBytes,
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
	}, nil
}

// logLevelFromEnv accepts exactly the four documented level names
// (case-insensitively). slog would also accept forms such as "info+2", but a
// misspelled level is far more likely to be a mistake than an intentional
// offset, so anything else fails loudly.
func logLevelFromEnv(key, fallback string) (string, error) {
	value := strings.ToLower(envOrDefault(key, fallback))
	switch value {
	case "debug", "info", "warn", "error":
		return value, nil
	}
	return "", fmt.Errorf("parse %s: must be one of debug, info, warn, or error", key)
}

// logFormatFromEnv accepts the two log encodings (case-insensitively) that
// internal/logging renders; anything else fails loudly like a bad level.
func logFormatFromEnv(key, fallback string) (string, error) {
	value := strings.ToLower(envOrDefault(key, fallback))
	switch value {
	case "json", "text":
		return value, nil
	}
	return "", fmt.Errorf("parse %s: must be one of json or text", key)
}

// endpointURLFromEnv validates an optional registry or auth endpoint override
// at load time: an absolute http(s) URL with a valid host and no credentials
// or fragment. The registry client applies its own, stricter policy (https
// unless the host is allowlisted) when it connects.
func endpointURLFromEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse %s: endpoint url is invalid", key)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("parse %s: endpoint url must use https or http", key)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("parse %s: endpoint url must be absolute and must not include credentials or a fragment", key)
	}
	if err := validateHostname(strings.ToLower(parsed.Hostname())); err != nil {
		return "", fmt.Errorf("parse %s: %w", key, err)
	}
	if port := parsed.Port(); port != "" {
		if err := validatePort(port); err != nil {
			return "", fmt.Errorf("parse %s: %w", key, err)
		}
	}
	return value, nil
}

// registryCredentialsFromEnv reads the optional RegistryUsername and
// RegistryPassword pair, which authenticates to the registry host of the
// scanned reference (or the configured registry endpoint) only. Either both
// are set or both are empty: a lone value is a configuration mistake that
// would otherwise surface only as an opaque 401 from the registry. The
// username is trimmed; the password is taken verbatim because surrounding
// whitespace may be part of it. Errors never include the values.
func registryCredentialsFromEnv(usernameKey, passwordKey string) (string, Secret, error) {
	username := strings.TrimSpace(os.Getenv(usernameKey))
	password := os.Getenv(passwordKey)
	switch {
	case username == "" && password == "":
		return "", "", nil
	case username == "":
		return "", "", fmt.Errorf("%s is set but %s is empty", passwordKey, usernameKey)
	case password == "":
		return "", "", fmt.Errorf("%s is set but %s is empty", usernameKey, passwordKey)
	}
	return username, Secret(password), nil
}

// regularFilePathFromEnv validates an optional file path (DockerConfigPath)
// at load time: when set it must name an existing regular file, so a typo in
// a credential file path fails at startup rather than at the first 401. Empty
// means the file is not consulted; there is no implicit default location.
func regularFilePathFromEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", nil
	}
	info, err := os.Stat(value) //nolint:gosec // the path is operator configuration and is only inspected here
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", key, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("parse %s: %s is not a regular file", key, value)
	}
	return value, nil
}

// listenAddrFromEnv validates a host:port listen address at load time so a
// malformed value fails before the database is opened.
func listenAddrFromEnv(key, fallback string) (string, error) {
	return validateListenAddr(key, envOrDefault(key, fallback))
}

// optionalListenAddrFromEnv is listenAddrFromEnv for a listener that is off
// when the variable is blank.
func optionalListenAddrFromEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", nil
	}
	return validateListenAddr(key, value)
}

func validateListenAddr(key, value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", key, err)
	}
	if err := validatePort(port); err != nil {
		return "", fmt.Errorf("parse %s: %w", key, err)
	}
	if host != "" && net.ParseIP(host) == nil {
		if err := validateHostname(strings.ToLower(host)); err != nil {
			return "", fmt.Errorf("parse %s: %w", key, err)
		}
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

// nonNegativeDurationFromEnv parses a duration that may be zero to disable
// the behaviour it configures.
func nonNegativeDurationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}

	if parsed < 0 {
		return 0, fmt.Errorf("%s must not be negative", key)
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

	switch strings.ToLower(value) {
	case "1", "t", "true", "yes", "y", "on":
		return true, nil
	case "0", "f", "false", "no", "n", "off":
		return false, nil
	}
	return false, fmt.Errorf("parse %s: must be one of 1, true, yes, on, 0, false, no, or off", key)
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
