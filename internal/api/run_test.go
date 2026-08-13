package api

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewDefaultLoggerHonorsConfiguredLevel(t *testing.T) {
	logger, err := newDefaultLogger("warn")
	if err != nil {
		t.Fatalf("newDefaultLogger() error = %v", err)
	}
	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info logging is enabled at warn level")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("warn logging is disabled at warn level")
	}
	if _, err := newDefaultLogger("verbose"); err == nil {
		t.Fatal("newDefaultLogger(verbose) error = nil")
	}
}
