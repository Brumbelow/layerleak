package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

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
	if err := validateEndpointURL(key, parsed); err != nil {
		return "", err
	}
	return value, nil
}

// validateEndpointURL checks, in order, the scheme, the absolute form without
// credentials or fragment, the hostname and the port of a parsed endpoint
// override named by key.
func validateEndpointURL(key string, parsed *url.URL) error {
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("parse %s: endpoint url must use https or http", key)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("parse %s: endpoint url must be absolute and must not include credentials or a fragment", key)
	}
	if err := validateHostname(strings.ToLower(parsed.Hostname())); err != nil {
		return fmt.Errorf("parse %s: %w", key, err)
	}
	if port := parsed.Port(); port != "" {
		if err := validatePort(port); err != nil {
			return fmt.Errorf("parse %s: %w", key, err)
		}
	}
	return nil
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

func validatePort(raw string) error {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}
