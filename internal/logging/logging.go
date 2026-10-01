// Package logging builds the slog handler both binaries write to stderr, so
// the CLI and layerleak-api accept the same LAYERLEAK_LOG_FORMAT values and
// render records identically.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Format names a log record encoding.
type Format string

const (
	// FormatJSON writes one JSON object per record (slog.NewJSONHandler); it
	// is the default because log shippers and CI collectors parse it safely.
	FormatJSON Format = "json"
	// FormatText writes key=value records (slog.NewTextHandler) for people
	// reading a terminal.
	FormatText Format = "text"
)

// Formats lists the accepted format names in documentation order.
var Formats = []Format{FormatJSON, FormatText}

// ParseFormat accepts exactly the documented format names, case-insensitively
// and ignoring surrounding whitespace; an empty value selects JSON.
func ParseFormat(value string) (Format, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "", string(FormatJSON):
		return FormatJSON, nil
	case string(FormatText):
		return FormatText, nil
	default:
		return "", fmt.Errorf("unsupported log format %q: use json or text", value)
	}
}

// ParseLevel accepts the slog level names (debug, info, warn, error) and the
// offset forms slog understands; LAYERLEAK_LOG_LEVEL is restricted to the
// four names before it reaches here.
func ParseLevel(value string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(value))); err != nil {
		return 0, fmt.Errorf("parse log level: %w", err)
	}
	return level, nil
}

// NewHandler returns the slog handler for format writing to output at level.
func NewHandler(output io.Writer, format Format, level slog.Level) (slog.Handler, error) {
	options := &slog.HandlerOptions{Level: level}
	switch format {
	case FormatJSON:
		return slog.NewJSONHandler(output, options), nil
	case FormatText:
		return slog.NewTextHandler(output, options), nil
	default:
		return nil, fmt.Errorf("unsupported log format %q: use json or text", string(format))
	}
}

// NewLogger parses the level and format names and returns a logger writing
// to output. It is the one constructor the CLI and the API share.
func NewLogger(output io.Writer, levelName, formatName string) (*slog.Logger, error) {
	level, err := ParseLevel(levelName)
	if err != nil {
		return nil, err
	}
	format, err := ParseFormat(formatName)
	if err != nil {
		return nil, err
	}
	handler, err := NewHandler(output, format, level)
	if err != nil {
		return nil, err
	}
	return slog.New(handler), nil
}
