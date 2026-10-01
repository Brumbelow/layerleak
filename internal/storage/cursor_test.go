package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
)

// placeholderCount returns the highest $n placeholder in a query so the tests
// can check that every bound argument is referenced and none is missing.
func placeholderCount(query string) int {
	highest := 0
	for index := 0; index < len(query); index++ {
		if query[index] != '$' {
			continue
		}
		number := 0
		for index+1 < len(query) && query[index+1] >= '0' && query[index+1] <= '9' {
			index++
			number = number*10 + int(query[index]-'0')
		}
		if number > highest {
			highest = number
		}
	}
	return highest
}

func TestListRepositoriesQueryUsesKeysetPredicateOnlyWithCursor(t *testing.T) {
	query, args := listRepositoriesQuery(50, 0, nil)
	if strings.Contains(query, "WHERE") || placeholderCount(query) != 2 || len(args) != 2 {
		t.Fatalf("offset query = %q args=%v", query, args)
	}
	if !strings.Contains(query, "ORDER BY last_seen_at DESC, repository ASC, registry ASC") {
		t.Fatalf("ordering changed: %q", query)
	}

	seenAt := time.Date(2026, time.September, 30, 17, 30, 0, 123456000, time.UTC)
	query, args = listRepositoriesQuery(50, 0, &RepositoryCursor{LastSeenAt: seenAt, Repository: "library/app", Registry: "docker.io"})
	if placeholderCount(query) != 5 || len(args) != 5 {
		t.Fatalf("keyset query = %q args=%v", query, args)
	}
	// Mixed directions cannot use a row comparison; the predicate expands the
	// (DESC, ASC, ASC) ordering explicitly.
	for _, want := range []string{
		"last_seen_at < $3",
		"last_seen_at = $3 AND repository > $4",
		"last_seen_at = $3 AND repository = $4 AND registry > $5",
		"LIMIT $1 OFFSET $2",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("keyset query lacks %q: %q", want, query)
		}
	}
	if args[2] != seenAt || args[3] != "library/app" || args[4] != "docker.io" {
		t.Fatalf("keyset args = %v", args)
	}
}

func TestListRepositoryScansQueryUsesRowComparisonWithCursor(t *testing.T) {
	query, args := listRepositoryScansQuery("docker.io", "library/app", 50, 10, nil)
	if strings.Contains(query, "(sr.scanned_at, sr.id)") || placeholderCount(query) != 4 || len(args) != 4 {
		t.Fatalf("offset query = %q args=%v", query, args)
	}
	scannedAt := time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC)
	query, args = listRepositoryScansQuery("docker.io", "library/app", 50, 0, &ScanRunCursor{ScannedAt: scannedAt, ID: 41})
	if placeholderCount(query) != 6 || len(args) != 6 {
		t.Fatalf("keyset query = %q args=%v", query, args)
	}
	if !strings.Contains(query, "AND (sr.scanned_at, sr.id) < ($5, $6)") || !strings.Contains(query, "ORDER BY sr.scanned_at DESC, sr.id DESC") {
		t.Fatalf("keyset predicate missing or ordering changed: %q", query)
	}
	if args[4] != scannedAt || args[5] != int64(41) {
		t.Fatalf("keyset args = %v", args)
	}
}

func TestListRepositoryFindingsQueryKeepsAggregateAndAddsKeyset(t *testing.T) {
	query, args := listRepositoryFindingsQuery("docker.io", "library/app", FindingDispositionAll, 50, 0, nil)
	if strings.Contains(query, "(f.last_seen_at, f.id)") || placeholderCount(query) != 7 || len(args) != 7 {
		t.Fatalf("offset query = %q args=%v", query, args)
	}
	if args[2] != string(findings.DispositionActionable) || args[3] != string(findings.DispositionExample) || args[4] != string(FindingDispositionAll) {
		t.Fatalf("disposition args = %v", args)
	}
	lastSeen := time.Date(2026, time.September, 30, 17, 30, 0, 0, time.UTC)
	query, args = listRepositoryFindingsQuery("docker.io", "library/app", FindingDispositionActionable, 50, 0, &FindingCursor{LastSeenAt: lastSeen, ID: 7})
	if placeholderCount(query) != 9 || len(args) != 9 {
		t.Fatalf("keyset query = %q args=%v", query, args)
	}
	// The keyset predicate filters finding rows before the GROUP BY so the
	// aggregate is computed only for the page, and the HAVING filter stays.
	whereIndex := strings.Index(query, "AND (f.last_seen_at, f.id) < ($8, $9)")
	groupIndex := strings.Index(query, "GROUP BY f.id")
	if whereIndex < 0 || groupIndex < 0 || whereIndex > groupIndex || !strings.Contains(query, "HAVING") {
		t.Fatalf("keyset predicate misplaced: %q", query)
	}
	if args[7] != lastSeen || args[8] != int64(7) {
		t.Fatalf("keyset args = %v", args)
	}
}
