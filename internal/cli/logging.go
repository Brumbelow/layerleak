package cli

import (
	"io"
	"log/slog"

	"github.com/brumbelow/layerleak/v3/internal/logging"
)

// newLogger writes log records to output, the command's stderr, so debug
// logging shares the stream (and the plain-progress fallback) with progress
// output instead of interleaving with a redrawn terminal block. format is
// json (the default, safe for log shippers) or text (for a terminal); the
// handler comes from internal/logging, which layerleak-api uses too.
func newLogger(level, format string, output io.Writer) (*slog.Logger, error) {
	return logging.NewLogger(output, level, format)
}

func parseLogLevel(level string) (slog.Level, error) {
	return logging.ParseLevel(level)
}
