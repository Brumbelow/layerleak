package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel                string
	APIAddr                 string
	RegistryBaseURL         string
	RegistryAuthURL         string
	HTTPTimeout             time.Duration
	MaxFileBytes            int64
	MaxLayerBytes           int64
	MaxLayerEntries         int
	MaxManifestBytes        int64
	MaxConfigBytes          int64
	TagPageSize             int
	MaxRepositoryTags       int
	MaxRepositoryTargets    int
	RegistryRequestAttempts int
	FindingsDir             string
	DatabaseURL             string
}

func Load() (Config, error) {
	timeout, err := durationFromEnv("LAYERLEAK_HTTP_TIMEOUT", 30*time.Second)
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
	maxManifestBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_MANIFEST_BYTES", 0)
	if err != nil {
		return Config{}, err
	}
	maxConfigBytes, err := nonNegativeInt64FromEnv("LAYERLEAK_MAX_CONFIG_BYTES", 0)
	if err != nil {
		return Config{}, err
	}
	tagPageSize, err := intFromEnv("LAYERLEAK_TAG_PAGE_SIZE", 100)
	if err != nil {
		return Config{}, err
	}
	maxRepositoryTags, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_REPOSITORY_TAGS", 0)
	if err != nil {
		return Config{}, err
	}
	maxRepositoryTargets, err := nonNegativeIntFromEnv("LAYERLEAK_MAX_REPOSITORY_TARGETS", 0)
	if err != nil {
		return Config{}, err
	}
	registryRequestAttempts, err := intFromEnv("LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS", 2)
	if err != nil {
		return Config{}, err
	}

	return Config{
		LogLevel:                envOrDefault("LAYERLEAK_LOG_LEVEL", "info"),
		APIAddr:                 envOrDefault("LAYERLEAK_API_ADDR", "127.0.0.1:8080"),
		RegistryBaseURL:         envOrDefault("LAYERLEAK_REGISTRY_BASE_URL", "https://registry-1.docker.io"),
		RegistryAuthURL:         envOrDefault("LAYERLEAK_REGISTRY_AUTH_URL", "https://auth.docker.io/token"),
		HTTPTimeout:             timeout,
		MaxFileBytes:            maxFileBytes,
		MaxLayerBytes:           maxLayerBytes,
		MaxLayerEntries:         maxLayerEntries,
		MaxManifestBytes:        maxManifestBytes,
		MaxConfigBytes:          maxConfigBytes,
		TagPageSize:             tagPageSize,
		MaxRepositoryTags:       maxRepositoryTags,
		MaxRepositoryTargets:    maxRepositoryTargets,
		RegistryRequestAttempts: registryRequestAttempts,
		FindingsDir:             strings.TrimSpace(os.Getenv("LAYERLEAK_FINDINGS_DIR")),
		DatabaseURL:             strings.TrimSpace(os.Getenv("LAYERLEAK_DATABASE_URL")),
	}, nil
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
