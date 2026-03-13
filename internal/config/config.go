package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel        string
	RegistryBaseURL string
	RegistryAuthURL string
	HTTPTimeout     time.Duration
	MaxFileBytes    int64
	FindingsDir     string
	DatabaseURL     string
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

	return Config{
		LogLevel:        envOrDefault("LAYERLEAK_LOG_LEVEL", "info"),
		RegistryBaseURL: envOrDefault("LAYERLEAK_REGISTRY_BASE_URL", "https://registry-1.docker.io"),
		RegistryAuthURL: envOrDefault("LAYERLEAK_REGISTRY_AUTH_URL", "https://auth.docker.io/token"),
		HTTPTimeout:     timeout,
		MaxFileBytes:    maxFileBytes,
		FindingsDir:     strings.TrimSpace(os.Getenv("LAYERLEAK_FINDINGS_DIR")),
		DatabaseURL:     strings.TrimSpace(os.Getenv("LAYERLEAK_DATABASE_URL")),
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
