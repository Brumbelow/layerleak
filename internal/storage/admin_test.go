package storage

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPurgeOptionsDefaults(t *testing.T) {
	if got := (PurgeOptions{}).withDefaults().BatchSize; got != 5000 || DefaultPurgeBatchSize != 5000 {
		t.Fatalf("default batch size = %d", got)
	}
	if got := (PurgeOptions{BatchSize: -3}).withDefaults().BatchSize; got != DefaultPurgeBatchSize {
		t.Fatalf("negative batch size = %d", got)
	}
	if got := (PurgeOptions{BatchSize: 7}).withDefaults().BatchSize; got != 7 {
		t.Fatalf("explicit batch size = %d", got)
	}
	// A nil Progress is simply not called.
	(PurgeOptions{}).report(PurgeProgress{})
}

// fakeTable simulates a table whose rows with raw material have the given
// ids; each purge call clears the next batch above afterID and records the
// requested bounds.
type fakeTable struct {
	ids   []int64
	calls [][2]int64 // afterID, size
	fail  map[int]error
}

func (f *fakeTable) purge(_ context.Context, _ purgeTarget, afterID int64, size int) (int64, int64, error) {
	f.calls = append(f.calls, [2]int64{afterID, int64(size)})
	if err, ok := f.fail[len(f.calls)]; ok {
		return 0, 0, err
	}
	var cleared []int64
	remaining := make([]int64, 0, len(f.ids))
	for _, id := range f.ids {
		if id > afterID && len(cleared) < size {
			cleared = append(cleared, id)
			continue
		}
		remaining = append(remaining, id)
	}
	f.ids = remaining
	if len(cleared) == 0 {
		return 0, 0, nil
	}
	return int64(len(cleared)), slices.Max(cleared), nil
}

func ids(from, to int64) []int64 {
	out := make([]int64, 0, to-from+1)
	for id := from; id <= to; id++ {
		out = append(out, id)
	}
	return out
}

// TestRunPurgeBatchesArithmetic pins the batching rules: batches walk ids
// upward from the last cleared id, a short batch ends the walk, an exactly
// full final batch costs one extra empty round trip, gaps in ids are fine, and
// progress reports every non-empty batch.
func TestRunPurgeBatchesArithmetic(t *testing.T) {
	tests := []struct {
		name      string
		ids       []int64
		size      int
		wantTotal int64
		wantCalls [][2]int64
		wantRows  []int64
	}{
		{name: "empty table", ids: nil, size: 5, wantTotal: 0, wantCalls: [][2]int64{{0, 5}}, wantRows: nil},
		{name: "short single batch", ids: ids(1, 3), size: 5, wantTotal: 3, wantCalls: [][2]int64{{0, 5}}, wantRows: []int64{3}},
		{name: "twelve rows in fives", ids: ids(1, 12), size: 5, wantTotal: 12, wantCalls: [][2]int64{{0, 5}, {5, 5}, {10, 5}}, wantRows: []int64{5, 5, 2}},
		{name: "exact multiple needs a final empty batch", ids: ids(1, 12), size: 4, wantTotal: 12, wantCalls: [][2]int64{{0, 4}, {4, 4}, {8, 4}, {12, 4}}, wantRows: []int64{4, 4, 4}},
		{name: "sparse ids advance by the last cleared id", ids: []int64{10, 20, 35, 36, 90}, size: 2, wantTotal: 5, wantCalls: [][2]int64{{0, 2}, {20, 2}, {36, 2}}, wantRows: []int64{2, 2, 1}},
		{name: "batch of one", ids: ids(1, 3), size: 1, wantTotal: 3, wantCalls: [][2]int64{{0, 1}, {1, 1}, {2, 1}, {3, 1}}, wantRows: []int64{1, 1, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := &fakeTable{ids: slices.Clone(test.ids)}
			var reported []int64
			total, err := runPurgeBatches(context.Background(), purgeTargetFindingValues, test.size, table.purge, func(rows int64) { reported = append(reported, rows) })
			if err != nil {
				t.Fatalf("runPurgeBatches() error = %v", err)
			}
			if total != test.wantTotal || len(table.ids) != 0 {
				t.Fatalf("total = %d (remaining %v), want %d", total, table.ids, test.wantTotal)
			}
			if !slices.Equal(table.calls, test.wantCalls) {
				t.Fatalf("calls = %v, want %v", table.calls, test.wantCalls)
			}
			if !slices.Equal(reported, test.wantRows) {
				t.Fatalf("progress = %v, want %v", reported, test.wantRows)
			}
		})
	}
}

func TestRunPurgeBatchesStopsOnErrorAndKeepsCommittedTotal(t *testing.T) {
	failure := errors.New("synthetic batch failure")
	table := &fakeTable{ids: ids(1, 12), fail: map[int]error{3: failure}}
	total, err := runPurgeBatches(context.Background(), purgeTargetFindingValues, 5, table.purge, nil)
	if !errors.Is(err, failure) || total != 10 {
		t.Fatalf("runPurgeBatches() = (%d, %v), want 10 rows and the batch error", total, err)
	}
	if len(table.calls) != 3 {
		t.Fatalf("calls after failure = %v", table.calls)
	}
}

func TestRunPurgeBatchesHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	table := &fakeTable{ids: ids(1, 100)}
	cancel()
	total, err := runPurgeBatches(ctx, purgeTargetFindingValues, 5, table.purge, nil)
	if !errors.Is(err, context.Canceled) || total != 0 || len(table.calls) != 0 {
		t.Fatalf("cancelled before start = (%d, %v, calls %v)", total, err, table.calls)
	}

	ctx, cancel = context.WithCancel(context.Background())
	table = &fakeTable{ids: ids(1, 100)}
	total, err = runPurgeBatches(ctx, purgeTargetFindingValues, 10, table.purge, func(int64) { cancel() })
	if !errors.Is(err, context.Canceled) || total != 10 || len(table.calls) != 1 {
		t.Fatalf("cancelled after first batch = (%d, %v, calls %v)", total, err, table.calls)
	}
}

func TestPurgeBatchSQLTargetsFixedIdentifiers(t *testing.T) {
	for _, target := range []purgeTarget{purgeTargetFindingValues, purgeTargetOccurrenceSnippets} {
		query := purgeBatchSQL(target)
		if placeholderCount(query) != 2 {
			t.Fatalf("%s: placeholders = %d, want 2 (after id, batch size)", target.table, placeholderCount(query))
		}
		for _, want := range []string{
			"FROM " + target.table,
			target.column + " <> ''",
			"id > $1",
			"ORDER BY id",
			"LIMIT $2",
			"UPDATE " + target.table + " AS t SET " + target.column + " = ''",
			"RETURNING t.id",
			"SELECT COUNT(*), COALESCE(MAX(id), 0) FROM cleared",
		} {
			if !strings.Contains(query, want) {
				t.Fatalf("%s query lacks %q:\n%s", target.table, want, query)
			}
		}
	}
}

func TestPurgeRawSecretsRejectsUninitialisedStore(t *testing.T) {
	var store *PostgresStore
	if _, err := store.PurgeRawSecrets(context.Background(), PurgeOptions{}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := (&PostgresStore{}).PurgeRawSecrets(context.Background(), PurgeOptions{}); err == nil {
		t.Fatal("store without database accepted")
	}
}
