package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
	"github.com/brumbelow/layerleak/v3/internal/version"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    mode
		wantErr string
	}{
		{name: "apply by default", args: nil, want: modeApply},
		{name: "status", args: []string{"--status"}, want: modeStatus},
		{name: "dry run", args: []string{"--dry-run"}, want: modeDryRun},
		{name: "version", args: []string{"--version"}, want: modeVersion},
		{name: "single dash", args: []string{"-status"}, want: modeStatus},
		{name: "positional argument", args: []string{"extra"}, wantErr: "positional"},
		{name: "status and dry run", args: []string{"--status", "--dry-run"}, wantErr: "mutually exclusive"},
		{name: "version and status", args: []string{"--version", "--status"}, wantErr: "mutually exclusive"},
		{name: "unknown flag", args: []string{"--down"}, wantErr: "flag provided but not defined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseMode(test.args, &bytes.Buffer{})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseMode(%v) error = %v, want %q", test.args, err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("parseMode(%v) = (%v, %v), want %v", test.args, got, err, test.want)
			}
		})
	}
}

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	for _, args := range [][]string{nil, {"--status"}, {"--dry-run"}} {
		code, err := run(args, &bytes.Buffer{}, &bytes.Buffer{})
		if code != exitError || err == nil || !strings.Contains(err.Error(), "LAYERLEAK_DATABASE_URL") {
			t.Fatalf("run(%v) = (%d, %v)", args, code, err)
		}
	}
}

func TestRunRejectsArguments(t *testing.T) {
	code, err := run([]string{"extra"}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != exitError || !errors.Is(err, errUsage) {
		t.Fatalf("run() = (%d, %v)", code, err)
	}
}

func TestRunVersionNeedsNoDatabase(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "")
	stdout := &bytes.Buffer{}
	code, err := run([]string{"--version"}, stdout, &bytes.Buffer{})
	if code != exitOK || err != nil {
		t.Fatalf("run(--version) = (%d, %v)", code, err)
	}
	if want := "layerleak-migrate-up " + version.Effective() + "\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestRunRejectsInvalidTimeoutsBeforeConnecting(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "postgres://layerleak@127.0.0.1:1/layerleak?sslmode=disable")

	t.Setenv("LAYERLEAK_MIGRATION_TIMEOUT", "soon")
	for _, args := range [][]string{nil, {"--status"}} {
		if code, err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != exitError || err == nil || !strings.Contains(err.Error(), "LAYERLEAK_MIGRATION_TIMEOUT") {
			t.Fatalf("run(%v) with invalid timeout = (%d, %v)", args, code, err)
		}
	}

	t.Setenv("LAYERLEAK_MIGRATION_TIMEOUT", "")
	t.Setenv("LAYERLEAK_MIGRATION_LOCK_TIMEOUT", "-5s")
	if code, err := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); code != exitError || err == nil || !strings.Contains(err.Error(), "LAYERLEAK_MIGRATION_LOCK_TIMEOUT") {
		t.Fatalf("run() with negative lock timeout = (%d, %v)", code, err)
	}
}

func TestDurationFromEnv(t *testing.T) {
	t.Setenv("LAYERLEAK_TEST_DURATION", "")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", 30*time.Minute); err != nil || got != 30*time.Minute {
		t.Fatalf("unset = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", " 90s ")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err != nil || got != 90*time.Second {
		t.Fatalf("90s = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", "0")
	if got, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err != nil || got != 0 {
		t.Fatalf("0 = (%s, %v)", got, err)
	}
	t.Setenv("LAYERLEAK_TEST_DURATION", "5 minutes")
	if _, err := durationFromEnv("LAYERLEAK_TEST_DURATION", time.Minute); err == nil || strings.Contains(err.Error(), "5 minutes") {
		t.Fatalf("invalid duration error = %v (must name the variable without echoing the value)", err)
	}
}

func TestMigrationContextAppliesDeadlineOnlyWhenPositive(t *testing.T) {
	ctx, cancel := migrationContext(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("zero timeout set a deadline")
	}

	bounded, cancelBounded := migrationContext(context.Background(), 30*time.Minute)
	defer cancelBounded()
	deadline, ok := bounded.Deadline()
	if !ok || time.Until(deadline) > 30*time.Minute || time.Until(deadline) < 29*time.Minute {
		t.Fatalf("deadline = %v (ok=%t)", deadline, ok)
	}
}

func pendingStatus() storage.MigrationStatusResult {
	appliedAt := time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC)
	return storage.MigrationStatusResult{
		Ledger:       `"public".schema_migrations`,
		LedgerExists: true,
		Current:      "0003",
		Expected:     "0004",
		Entries: []storage.MigrationStatusEntry{
			{Version: "0001", Name: "0001_initial", Checksum: strings.Repeat("1", 64), Applied: true, AppliedAt: appliedAt},
			{Version: "0002", Name: "0002_history", Checksum: strings.Repeat("2", 64), Applied: true, AppliedAt: appliedAt.Add(time.Minute)},
			{Version: "0003", Name: "0003_dispositions", Checksum: strings.Repeat("3", 64), Applied: true, AppliedAt: appliedAt.Add(2 * time.Minute)},
			{Version: "0004", Name: "0004_hardening", Checksum: strings.Repeat("4", 64)},
		},
		Pending:   []string{"0004_hardening"},
		Adoptable: []string{},
	}
}

func TestRenderStatusPendingLedger(t *testing.T) {
	out := &bytes.Buffer{}
	status := pendingStatus()
	renderStatus(out, status)
	for _, want := range []string{
		`ledger: "public".schema_migrations (present)`,
		"VERSION  NAME               STATE    APPLIED AT            SHA256",
		"0001     0001_initial       applied  2026-09-30T17:30:00Z  " + strings.Repeat("1", 64),
		"0004     0004_hardening     pending  -                     " + strings.Repeat("4", 64),
		"current: 0003  expected: 0004  pending: 1  adoptable: 0",
		"migrations are pending; run layerleak-migrate-up to apply them",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output lacks %q:\n%s", want, out.String())
		}
	}
	if statusExitCode(status) != exitPending {
		t.Fatalf("statusExitCode(pending) = %d", statusExitCode(status))
	}
}

func TestRenderStatusCurrentAndEmpty(t *testing.T) {
	status := pendingStatus()
	status.Entries[3].Applied = true
	status.Entries[3].AppliedAt = time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	status.Pending = nil
	status.Current = "0004"
	out := &bytes.Buffer{}
	renderStatus(out, status)
	if !strings.Contains(out.String(), "current: 0004  expected: 0004  pending: 0  adoptable: 0") || !strings.Contains(out.String(), "database schema is up to date at 0004") {
		t.Fatalf("current output:\n%s", out.String())
	}
	if statusExitCode(status) != exitOK {
		t.Fatalf("statusExitCode(current) = %d", statusExitCode(status))
	}

	empty := storage.MigrationStatusResult{Ledger: `"public".schema_migrations`, Expected: "0004", Pending: []string{"0001_initial"}, Entries: []storage.MigrationStatusEntry{{Version: "0001", Name: "0001_initial", Checksum: strings.Repeat("1", 64)}}}
	out.Reset()
	renderStatus(out, empty)
	if !strings.Contains(out.String(), "(absent)") || !strings.Contains(out.String(), "current: none  expected: 0004") {
		t.Fatalf("empty output:\n%s", out.String())
	}
	if statusExitCode(empty) != exitPending {
		t.Fatalf("statusExitCode(empty) = %d", statusExitCode(empty))
	}
}

func TestRenderStatusLegacyAdoptable(t *testing.T) {
	status := pendingStatus()
	status.LedgerExists = false
	for index := range status.Entries[:3] {
		status.Entries[index].Applied = false
		status.Entries[index].AppliedAt = time.Time{}
		status.Entries[index].Adoptable = true
	}
	status.Adoptable = []string{"0001_initial", "0002_history", "0003_dispositions"}
	out := &bytes.Buffer{}
	renderStatus(out, status)
	if !strings.Contains(out.String(), "0001     0001_initial       adoptable  -") || !strings.Contains(out.String(), "pending: 1  adoptable: 3") {
		t.Fatalf("legacy output:\n%s", out.String())
	}
	if statusExitCode(status) != exitPending {
		t.Fatalf("statusExitCode(legacy) = %d", statusExitCode(status))
	}
}

func TestRenderDryRun(t *testing.T) {
	out := &bytes.Buffer{}
	renderDryRun(out, pendingStatus())
	if out.String() != "would apply 0004_hardening\ndry run: database schema would move from 0003 to 0004; nothing was changed\n" {
		t.Fatalf("pending dry run:\n%s", out.String())
	}

	legacy := pendingStatus()
	legacy.Adoptable = []string{"0001_initial", "0002_history", "0003_dispositions"}
	out.Reset()
	renderDryRun(out, legacy)
	if !strings.HasPrefix(out.String(), "would adopt 0001_initial (legacy schema already matches") || !strings.Contains(out.String(), "would apply 0004_hardening\n") {
		t.Fatalf("legacy dry run:\n%s", out.String())
	}

	current := pendingStatus()
	current.Pending = nil
	current.Current = "0004"
	out.Reset()
	renderDryRun(out, current)
	if out.String() != "database schema is up to date at 0004; nothing to apply\n" {
		t.Fatalf("current dry run:\n%s", out.String())
	}

	empty := storage.MigrationStatusResult{Expected: "0004", Pending: []string{"0001_initial", "0002_history"}}
	out.Reset()
	renderDryRun(out, empty)
	if out.String() != "would apply 0001_initial\nwould apply 0002_history\ndry run: database schema would move from none to 0004; nothing was changed\n" {
		t.Fatalf("empty dry run:\n%s", out.String())
	}
}

func TestTimeoutHint(t *testing.T) {
	base := errors.New("synthetic failure")
	if got := timeoutHint(context.Background(), base, time.Minute); got != base {
		t.Fatalf("live context changed the error: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := timeoutHint(ctx, base, time.Minute); !errors.Is(got, base) || !strings.Contains(got.Error(), "LAYERLEAK_MIGRATION_TIMEOUT=1m0s") {
		t.Fatalf("expired context hint = %v", got)
	}
	if got := timeoutHint(ctx, base, 0); got != base {
		t.Fatalf("disabled timeout changed the error: %v", got)
	}
}

func TestRunHelpExitsCleanly(t *testing.T) {
	for _, flagName := range []string{"-h", "-help", "--help"} {
		var stderr bytes.Buffer
		code, err := run([]string{flagName}, &bytes.Buffer{}, &stderr)
		if err != nil || code != exitOK {
			t.Fatalf("run(%s) = %d, %v", flagName, code, err)
		}
		if !strings.Contains(stderr.String(), "-status") {
			t.Fatalf("run(%s) did not print usage: %q", flagName, stderr.String())
		}
	}
}
