package main

import (
	"os"
	"strings"
	"testing"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	oldArgs := os.Args
	os.Args = []string{"layerleak-migrate-up"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DATABASE_URL") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"layerleak-migrate-up", "extra"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil {
		t.Fatal("run() error = nil")
	}
}
