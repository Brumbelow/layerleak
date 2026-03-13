package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

func writeResultFile(configuredDir string, result scanner.Result) (string, error) {
	findingsDir, err := resolveFindingsDir(configuredDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		return "", fmt.Errorf("create findings directory: %w", err)
	}

	filePath := filepath.Join(findingsDir, buildResultFileName(result))
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("create findings result file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return "", fmt.Errorf("write findings result file: %w", err)
	}

	return filePath, nil
}

func resolveFindingsDir(configuredDir string) (string, error) {
	value := strings.TrimSpace(configuredDir)
	if value != "" {
		if filepath.IsAbs(value) {
			return value, nil
		}
		root, err := repoRoot()
		if err != nil {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return "", fmt.Errorf("resolve current working directory: %w", cwdErr)
			}
			return filepath.Clean(filepath.Join(cwd, value)), nil
		}
		return filepath.Clean(filepath.Join(root, value)), nil
	}

	root, err := repoRoot()
	if err != nil {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", fmt.Errorf("resolve current working directory: %w", cwdErr)
		}
		root = cwd
	}

	return filepath.Join(root, "findings"), nil
}

func repoRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("repo root not found")
		}
		current = parent
	}
}

func buildResultFileName(result scanner.Result) string {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	digest := sanitizePathToken(result.RequestedDigest)
	if digest == "" {
		digest = "unknown-digest"
	}

	return fmt.Sprintf("%s-%s.json", timestamp, digest)
}

func sanitizePathToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-', r == '_':
			builder.WriteRune(r)
		case r == ':', r == '/', r == '.', r == ' ':
			builder.WriteRune('-')
		}
	}

	return strings.Trim(builder.String(), "-")
}
