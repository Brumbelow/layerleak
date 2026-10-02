package storage

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestPostgresStoreBareConfigRetainsIdleConnections is the DB-05 regression
// test: withDefaults left MaxIdleConns at 0, so a PostgresConfig that only set
// DatabaseURL dialled and dropped a connection for every statement.
func TestPostgresStoreBareConfigRetainsIdleConnections(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()
	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t)})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	for index := 0; index < 3; index++ {
		if _, err := store.ListRepositories(context.Background(), 10, 0, nil); err != nil {
			t.Fatalf("ListRepositories() error = %v", err)
		}
	}
	stats := store.db.Stats()
	if stats.Idle < 1 || stats.MaxIdleClosed != 0 {
		t.Fatalf("bare config pool after 3 queries: Open=%d Idle=%d MaxIdleClosed=%d; want an idle connection retained", stats.OpenConnections, stats.Idle, stats.MaxIdleClosed)
	}
}

// keywordIntegrationDSN rewrites the integration URL into libpq keyword form so
// the same disposable server is reached through the alternative grammar.
func keywordIntegrationDSN(t *testing.T) string {
	t.Helper()
	parsed, err := url.Parse(integrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	pairs := []string{
		"host=" + parsed.Hostname(),
		"dbname=" + strings.TrimPrefix(parsed.Path, "/"),
	}
	if port := parsed.Port(); port != "" {
		pairs = append(pairs, "port="+port)
	}
	if user := parsed.User.Username(); user != "" {
		pairs = append(pairs, "user="+user)
	}
	if password, ok := parsed.User.Password(); ok {
		pairs = append(pairs, fmt.Sprintf("password='%s'", strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(password)))
	}
	for key, values := range parsed.Query() {
		pairs = append(pairs, key+"="+values[0])
	}
	return strings.Join(pairs, " ")
}

// queryHostIntegrationDSN moves the host into the query string, the form used
// for unix sockets (host=/var/run/postgresql) and Cloud SQL Auth Proxy setups.
func queryHostIntegrationDSN(t *testing.T) string {
	t.Helper()
	parsed, err := url.Parse(integrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	values := parsed.Query()
	values.Set("host", parsed.Hostname())
	if port := parsed.Port(); port != "" {
		values.Set("port", port)
	}
	if user := parsed.User.Username(); user != "" {
		values.Set("user", user)
	}
	if password, ok := parsed.User.Password(); ok {
		values.Set("password", password)
	}
	parsed.User = nil
	parsed.Host = ""
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

// TestPostgresStoreAcceptsAlternativeDSNGrammars is the DB-14 regression test:
// Validate rejected both forms before lib/pq ever saw them, locking socket-only
// deployments out of the API, CLI, purge and migrate binaries.
func TestPostgresStoreAcceptsAlternativeDSNGrammars(t *testing.T) {
	for name, dsn := range map[string]string{
		"libpq keywords":    keywordIntegrationDSN(t),
		"query string host": queryHostIntegrationDSN(t),
	} {
		t.Run(name, func(t *testing.T) {
			db := openIntegrationDB(t)
			defer func() { _ = db.Close() }()

			result, err := RunMigrations(context.Background(), MigrationConfig{DatabaseURL: dsn, Directory: repoRoot(t) + "/migrations"})
			if err != nil {
				t.Fatalf("RunMigrations() error = %v", err)
			}
			if len(result.Applied) != currentMigrationCount {
				t.Fatalf("result = %+v", result)
			}

			store, err := NewPostgresStore(PostgresConfig{DatabaseURL: dsn, RequireSchema: true})
			if err != nil {
				t.Fatalf("NewPostgresStore() error = %v", err)
			}
			defer func() { _ = store.Close() }()
			if err := store.Ready(context.Background()); err != nil {
				t.Fatalf("Ready() error = %v", err)
			}
			repositories, err := store.ListRepositories(context.Background(), 10, 0, nil)
			if err != nil || len(repositories) != 0 {
				t.Fatalf("ListRepositories() = %v, %v", repositories, err)
			}
		})
	}
}
