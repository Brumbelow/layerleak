package main

import (
	"os"
	"strings"
	"testing"
)

func TestRunRejectsInvalidAPIAddress(t *testing.T) {
	t.Setenv("LAYERLEAK_API_ADDR", "not-an-address")
	oldArgs := os.Args
	os.Args = []string{"layerleak-healthcheck"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil || !strings.Contains(err.Error(), "parse LAYERLEAK_API_ADDR") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"layerleak-healthcheck", "extra"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := run(); err == nil {
		t.Fatal("run() error = nil")
	}
}
