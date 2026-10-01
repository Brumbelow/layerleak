package storage

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestPostgresStoreKeysetPagesMatchOffsetPages walks each list endpoint by
// cursor and by offset over data with ordering ties and requires identical
// sequences, so the keyset predicates agree with the ORDER BY clauses.
func TestPostgresStoreKeysetPagesMatchOffsetPages(t *testing.T) {
	db := openMigratedIntegrationDB(t)
	defer func() { _ = db.Close() }()

	seenAt := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		registry   string
		repository string
		seenAt     time.Time
	}{
		{"z.example", "library/app", seenAt},
		{"m.example", "library/app", seenAt},
		{"a.example", "library/app", seenAt},
		{"z.example", "library/aaa", seenAt},
		{"a.example", "library/older", seenAt.Add(-time.Hour)},
		{"docker.io", "library/app", seenAt.Add(-2 * time.Hour)},
	} {
		if _, err := db.Exec(`
			INSERT INTO repositories (registry, repository, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $3)
		`, item.registry, item.repository, item.seenAt); err != nil {
			t.Fatalf("insert repository: %v", err)
		}
	}

	store, err := NewPostgresStore(PostgresConfig{DatabaseURL: integrationDatabaseURL(t), PersistRawSecrets: false})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// Seven scans of docker.io/library/app, three sharing one timestamp, each
	// carrying one distinct finding so finding rows tie on last_seen_at too.
	for index := 0; index < 7; index++ {
		scannedAt := seenAt.Add(-time.Duration(index/3) * time.Minute)
		record := integrationScanRecord(scannedAt)
		record.DetailedFindings = record.DetailedFindings[:1]
		record.DetailedFindings[0].Fingerprint = fmt.Sprintf("%064d", index)
		if _, err := store.SaveScan(context.Background(), record); err != nil {
			t.Fatalf("SaveScan(%d) error = %v", index, err)
		}
	}

	t.Run("repositories", func(t *testing.T) {
		var byOffset []string
		for offset := 0; ; offset += 2 {
			items, err := store.ListRepositories(context.Background(), 2, offset, nil)
			if err != nil {
				t.Fatalf("ListRepositories(offset=%d): %v", offset, err)
			}
			for _, item := range items {
				byOffset = append(byOffset, item.Registry+"/"+item.Repository)
			}
			if len(items) < 2 {
				break
			}
		}
		var byCursor []string
		var after *RepositoryCursor
		for pages := 0; pages < 10; pages++ {
			items, err := store.ListRepositories(context.Background(), 2, 0, after)
			if err != nil {
				t.Fatalf("ListRepositories(cursor): %v", err)
			}
			for _, item := range items {
				byCursor = append(byCursor, item.Registry+"/"+item.Repository)
			}
			if len(items) < 2 {
				break
			}
			last := items[len(items)-1]
			after = &RepositoryCursor{LastSeenAt: last.LastSeenAt, Repository: last.Repository, Registry: last.Registry}
		}
		if len(byOffset) != 6 || !slices.Equal(byOffset, byCursor) {
			t.Fatalf("offset pages %v != cursor pages %v", byOffset, byCursor)
		}
	})

	t.Run("scans", func(t *testing.T) {
		var byOffset, byCursor []int64
		for offset := 0; ; offset += 3 {
			items, err := store.ListRepositoryScans(context.Background(), "docker.io", "library/app", 3, offset, nil)
			if err != nil {
				t.Fatalf("ListRepositoryScans(offset=%d): %v", offset, err)
			}
			for _, item := range items {
				byOffset = append(byOffset, item.ID)
			}
			if len(items) < 3 {
				break
			}
		}
		var after *ScanRunCursor
		for pages := 0; pages < 10; pages++ {
			items, err := store.ListRepositoryScans(context.Background(), "docker.io", "library/app", 3, 0, after)
			if err != nil {
				t.Fatalf("ListRepositoryScans(cursor): %v", err)
			}
			for _, item := range items {
				byCursor = append(byCursor, item.ID)
			}
			if len(items) < 3 {
				break
			}
			last := items[len(items)-1]
			after = &ScanRunCursor{ScannedAt: last.ScannedAt, ID: last.ID}
		}
		if len(byOffset) != 7 || !slices.Equal(byOffset, byCursor) {
			t.Fatalf("offset pages %v != cursor pages %v", byOffset, byCursor)
		}
	})

	t.Run("findings", func(t *testing.T) {
		var byOffset, byCursor []int64
		for offset := 0; ; offset += 2 {
			items, err := store.ListRepositoryFindings(context.Background(), "docker.io", "library/app", FindingDispositionAll, 2, offset, nil)
			if err != nil {
				t.Fatalf("ListRepositoryFindings(offset=%d): %v", offset, err)
			}
			for _, item := range items {
				byOffset = append(byOffset, item.ID)
			}
			if len(items) < 2 {
				break
			}
		}
		var after *FindingCursor
		for pages := 0; pages < 10; pages++ {
			items, err := store.ListRepositoryFindings(context.Background(), "docker.io", "library/app", FindingDispositionAll, 2, 0, after)
			if err != nil {
				t.Fatalf("ListRepositoryFindings(cursor): %v", err)
			}
			for _, item := range items {
				byCursor = append(byCursor, item.ID)
			}
			if len(items) < 2 {
				break
			}
			last := items[len(items)-1]
			after = &FindingCursor{LastSeenAt: last.LastSeenAt, ID: last.ID}
		}
		if len(byOffset) != 7 || !slices.Equal(byOffset, byCursor) {
			t.Fatalf("offset pages %v != cursor pages %v", byOffset, byCursor)
		}
	})
}
