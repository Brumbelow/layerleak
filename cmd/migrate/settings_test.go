package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/storage"
)

// TestMigrationSettingsFromEnv pins the defaults and trimming of the
// environment-supplied run configuration and the progress writer.
func TestMigrationSettingsFromEnv(t *testing.T) {
	t.Setenv("LAYERLEAK_DATABASE_URL", "  postgres://layerleak@127.0.0.1:1/layerleak  ")
	t.Setenv("LAYERLEAK_MIGRATIONS_DIR", "  ")
	t.Setenv(migrationTimeoutEnv, "")
	t.Setenv(migrationLockTimeoutEnv, "")
	settings, err := migrationSettingsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := migrationSettings{
		databaseURL:   "postgres://layerleak@127.0.0.1:1/layerleak",
		migrationsDir: "/app/migrations",
		timeout:       defaultMigrationTimeout,
		lockTimeout:   storage.DefaultMigrationLockTimeout,
	}
	if settings != want {
		t.Fatalf("settings = %+v, want %+v", settings, want)
	}

	t.Setenv("LAYERLEAK_MIGRATIONS_DIR", " /srv/migrations ")
	t.Setenv(migrationTimeoutEnv, "0")
	t.Setenv(migrationLockTimeoutEnv, "5s")
	settings, err = migrationSettingsFromEnv()
	if err != nil || settings.migrationsDir != "/srv/migrations" || settings.timeout != 0 || settings.lockTimeout != 5*time.Second {
		t.Fatalf("settings = %+v, %v", settings, err)
	}

	var stderr bytes.Buffer
	config := settings.migrationConfig(&stderr)
	if config.DatabaseURL != settings.databaseURL || config.Directory != "/srv/migrations" || config.LockTimeout != 5*time.Second {
		t.Fatalf("config = %+v", config)
	}
	config.Progress("applying migration 0001_initial")
	if stderr.String() != "applying migration 0001_initial\n" {
		t.Fatalf("progress output = %q", stderr.String())
	}
}
