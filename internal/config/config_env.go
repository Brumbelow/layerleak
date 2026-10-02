package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

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
