package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    options
		wantErr string
	}{
		{name: "no flags refuses", args: nil, wantErr: "--confirm"},
		{name: "confirm", args: []string{"--confirm"}, want: options{confirm: true, batchSize: 5000}},
		{name: "dry run needs no confirm", args: []string{"--dry-run"}, want: options{dryRun: true, batchSize: 5000}},
		{name: "dry run with confirm stays a dry run", args: []string{"--dry-run", "--confirm"}, want: options{dryRun: true, confirm: true, batchSize: 5000}},
		{name: "batch size", args: []string{"--confirm", "--batch-size", "250"}, want: options{confirm: true, batchSize: 250}},
		{name: "batch size equals form", args: []string{"--confirm", "--batch-size=1"}, want: options{confirm: true, batchSize: 1}},
		{name: "zero batch size", args: []string{"--confirm", "--batch-size", "0"}, wantErr: "--batch-size must be greater than zero"},
		{name: "negative batch size", args: []string{"--dry-run", "--batch-size=-5"}, wantErr: "--batch-size must be greater than zero"},
		{name: "non numeric batch size", args: []string{"--confirm", "--batch-size", "many"}, wantErr: "invalid value"},
		{name: "positional argument", args: []string{"--confirm", "extra"}, wantErr: "positional"},
		{name: "unknown flag", args: []string{"--force"}, wantErr: "flag provided but not defined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			got, err := parseOptions(test.args, stderr)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseOptions(%v) error = %v, want %q", test.args, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOptions(%v) error = %v", test.args, err)
			}
			if got != test.want {
				t.Fatalf("parseOptions(%v) = %+v, want %+v", test.args, got, test.want)
			}
		})
	}
}

func TestRunRequiresConfirmation(t *testing.T) {
	err := run(nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRequiresDatabaseAfterConfirmation(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	t.Setenv("LAYERLEAK_PURGE_TIMEOUT", "")
	for _, args := range [][]string{{"--confirm"}, {"--dry-run"}} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DATABASE_URL") {
			t.Fatalf("run(%v) error = %v", args, err)
		}
	}
}

func TestRunRejectsInvalidPurgeTimeoutBeforeConnecting(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "postgres://layerleak@127.0.0.1:1/layerleak?sslmode=disable")
	t.Setenv("LAYERLEAK_PURGE_TIMEOUT", "soon")
	err := run([]string{"--confirm"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "LAYERLEAK_PURGE_TIMEOUT") || strings.Contains(err.Error(), "soon") {
		t.Fatalf("run() error = %v (must name the variable without echoing the value)", err)
	}
	t.Setenv("LAYERLEAK_PURGE_TIMEOUT", "-1m")
	if err := run([]string{"--dry-run"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("run() with negative timeout error = %v", err)
	}
}

func TestDurationFromEnv(t *testing.T) {
	t.Setenv("LAYERLEAK_TEST_PURGE_DURATION", "")
	if got, err := durationFromEnv("LAYERLEAK_TEST_PURGE_DURATION", 30*time.Minute); err != nil || got != 30*time.Minute {
		t.Fatalf("unset = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_PURGE_DURATION", " 90s ")
	if got, err := durationFromEnv("LAYERLEAK_TEST_PURGE_DURATION", time.Minute); err != nil || got != 90*time.Second {
		t.Fatalf("90s = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_PURGE_DURATION", "0")
	if got, err := durationFromEnv("LAYERLEAK_TEST_PURGE_DURATION", time.Minute); err != nil || got != 0 {
		t.Fatalf("0 = (%s, %v)", got, err)
	}
}

func TestPurgeContextAppliesDeadlineOnlyWhenPositive(t *testing.T) {
	ctx, cancel := purgeContext(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("zero timeout set a deadline")
	}
	bounded, cancelBounded := purgeContext(context.Background(), 30*time.Minute)
	defer cancelBounded()
	deadline, ok := bounded.Deadline()
	if !ok || time.Until(deadline) > 30*time.Minute || time.Until(deadline) < 29*time.Minute {
		t.Fatalf("deadline = %v (ok=%t)", deadline, ok)
	}
}

func TestRunHelpExitsCleanly(t *testing.T) {
	for _, flagName := range []string{"-h", "-help", "--help"} {
		var stderr bytes.Buffer
		if err := run([]string{flagName}, &bytes.Buffer{}, &stderr); err != nil {
			t.Fatalf("run(%s) error = %v", flagName, err)
		}
		if !strings.Contains(stderr.String(), "-confirm") {
			t.Fatalf("run(%s) did not print usage: %q", flagName, stderr.String())
		}
	}
}
