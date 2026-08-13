package main

import (
	"os"
	"strings"
	"testing"
)

func TestRunRequiresConfirmation(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"layerleak-purge-raw-secrets"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRequiresDatabaseAfterConfirmation(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	oldArgs := os.Args
	os.Args = []string{"layerleak-purge-raw-secrets", "--confirm"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DATABASE_URL") {
		t.Fatalf("run() error = %v", err)
	}
}
