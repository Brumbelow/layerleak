// Package main runs the Layerleak HTTP API. It is a thin wrapper around
// api.Run so the server itself is tested in internal/api.
package main

import (
	"io"
	"log/slog"
	"os"

	"github.com/brumbelow/layerleak/v3/internal/api"
)

func main() {
	os.Exit(run(os.Stderr, api.Run))
}

// run executes serve and reports a failure as one JSON log record on stderr,
// matching the JSON handler the API installs once configuration has loaded,
// so log shippers never see a bare text line. It returns the exit status.
func run(stderr io.Writer, serve func() error) int {
	if err := serve(); err != nil {
		logger := slog.New(slog.NewJSONHandler(stderr, nil))
		logger.Error("api server exited with an error", "error", err.Error())
		return 1
	}
	return 0
}
