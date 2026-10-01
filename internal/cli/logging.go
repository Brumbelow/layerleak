package cli

import (
	"fmt"
	"io"
	"log/slog"
)

// newLogger writes JSON log lines to output, the command's stderr, so debug
// logging shares the stream (and the plain-progress fallback) with progress
// output instead of interleaving with a redrawn terminal block.
func newLogger(level string, output io.Writer) (*slog.Logger, error) {
	parsed, err := parseLogLevel(level)
	if err != nil {
		return nil, err
	}

	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level: parsed,
	})), nil
}

func parseLogLevel(level string) (slog.Level, error) {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		return 0, fmt.Errorf("parse log level: %w", err)
	}
	return parsed, nil
}
