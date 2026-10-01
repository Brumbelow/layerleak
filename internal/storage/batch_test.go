package storage

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

func batchTestFinding(fingerprint, key string, line int, raw string) findings.DetailedFinding {
	return findings.DetailedFinding{
		Finding: findings.Finding{
			DetectorName:        "github_token",
			Confidence:          "high",
			Disposition:         findings.DispositionActionable,
			SourceType:          findings.SourceTypeEnv,
			ManifestDigest:      " sha256:bbb ",
			Platform:            manifest.Platform{OS: "linux", Architecture: "amd64"},
			Key:                 key,
			RedactedValue:       "red-" + raw,
			Fingerprint:         " " + fingerprint + " ",
			ContextSnippet:      key + "=[REDACTED]",
			LineNumber:          line,
			PresentInFinalImage: true,
		},
		Value:          "raw-" + raw,
		RawSnippet:     key + "=raw-" + raw,
		SourceLocation: "env:" + key,
	}
}

func TestCollapseFindingsKeepsOneRowPerIdentityWithLastValue(t *testing.T) {
	items := []findings.DetailedFinding{
		batchTestFinding("fp-1", "A", 1, "first"),
		batchTestFinding("fp-2", "B", 1, "other"),
		batchTestFinding("fp-1", "C", 1, "last"),
	}

	rows := collapseFindings(items, true)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].key != (findingKey{manifestDigest: "sha256:bbb", fingerprint: "fp-1"}) {
		t.Fatalf("rows[0].key = %+v, want trimmed identity in first-appearance order", rows[0].key)
	}
	if rows[0].redactedValue != "red-last" || rows[0].value != "raw-last" {
		t.Fatalf("rows[0] = %+v, want the last sorted values", rows[0])
	}
	if rows[1].key.fingerprint != "fp-2" || rows[1].value != "raw-other" {
		t.Fatalf("rows[1] = %+v", rows[1])
	}

	redactedOnly := collapseFindings(items, false)
	if redactedOnly[0].value != "" || redactedOnly[0].redactedValue != "red-last" {
		t.Fatalf("collapseFindings(persistRawSecrets=false) = %+v", redactedOnly[0])
	}
}

func TestCollapseOccurrencesCollapsesDatabaseIdentity(t *testing.T) {
	items := []findings.DetailedFinding{
		batchTestFinding("fp-1", "A", 1, "line-one"),
		batchTestFinding("fp-1", "A", 2, "line-two"), // same 15-column identity, different line
		batchTestFinding("fp-1", "B", 1, "other-key"),
		batchTestFinding("fp-2", "A", 1, "other-finding"),
	}
	items[2].Disposition = findings.DispositionExample
	items[2].DispositionReason = findings.DispositionReason("test-path")

	rows := collapseOccurrences(items, true)
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	first := rows[0]
	if first.identity.key.fingerprint != "fp-1" || first.identity.sourceKey != "A" {
		t.Fatalf("rows[0].identity = %+v", first.identity)
	}
	if first.lineNumber != 2 || first.rawSnippet != "A=raw-line-two" {
		t.Fatalf("rows[0] mutable columns = (line %d, %q), want the last sorted row", first.lineNumber, first.rawSnippet)
	}
	if rows[1].disposition != string(findings.DispositionExample) || rows[1].dispositionReason != "test-path" {
		t.Fatalf("rows[1] = %+v", rows[1])
	}
	if rows[2].identity.key.fingerprint != "fp-2" {
		t.Fatalf("rows[2] = %+v", rows[2])
	}

	redactedOnly := collapseOccurrences(items, false)
	for _, row := range redactedOnly {
		if row.rawSnippet != "" {
			t.Fatalf("collapseOccurrences(persistRawSecrets=false) kept raw snippet %q", row.rawSnippet)
		}
	}
}

func TestUpsertFindingOccurrencesBatchSQLArity(t *testing.T) {
	query := strings.Join(strings.Fields(upsertFindingOccurrencesBatchSQL), " ")
	columns, remainder, ok := strings.Cut(query, ") SELECT batch.*, $20, $20 FROM unnest( ")
	if !ok {
		t.Fatalf("upsertFindingOccurrencesBatchSQL does not select the batch plus the timestamp twice: %s", query)
	}
	columnList := strings.Split(strings.TrimSpace(strings.TrimPrefix(columns, "INSERT INTO finding_occurrences (")), ", ")
	arrays, remainder, ok := strings.Cut(remainder, " ) AS batch( ")
	if !ok {
		t.Fatal("upsertFindingOccurrencesBatchSQL is missing the batch alias")
	}
	arrayList := strings.Split(arrays, ", ")
	aliases, _, ok := strings.Cut(remainder, " ) ON CONFLICT (")
	if !ok {
		t.Fatal("upsertFindingOccurrencesBatchSQL is missing ON CONFLICT")
	}
	aliasList := strings.Split(aliases, ", ")

	if len(columnList) != 21 {
		t.Fatalf("INSERT names %d columns, want 21: %v", len(columnList), columnList)
	}
	if len(arrayList) != 19 || len(aliasList) != 19 {
		t.Fatalf("unnest has %d arrays and %d aliases, want 19 each", len(arrayList), len(aliasList))
	}
	if !slices.Equal(aliasList, columnList[:19]) {
		t.Fatalf("batch aliases %v do not match the first 19 insert columns %v", aliasList, columnList[:19])
	}
	if columnList[19] != "first_seen_at" || columnList[20] != "last_seen_at" {
		t.Fatalf("timestamp columns = %v", columnList[19:])
	}
	for index, array := range arrayList {
		if !strings.HasPrefix(array, "$"+strconv.Itoa(index+1)+"::") {
			t.Fatalf("unnest argument %d = %q, want $%d", index+1, array, index+1)
		}
	}
	if !strings.Contains(query, "WHEN $21 AND") {
		t.Fatal("upsertFindingOccurrencesBatchSQL does not use argument 21 for the raw-secret flag")
	}
	if got := len(newOccurrenceBatch(1).args(time.Time{}, true)); got != 21 {
		t.Fatalf("occurrenceBatch.args() has %d parameters, want 21", got)
	}
}

func TestUpsertFindingsBatchSQLArity(t *testing.T) {
	query := strings.Join(strings.Fields(upsertFindingsBatchSQL), " ")
	if !strings.Contains(query, "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS batch(manifest_digest, fingerprint, redacted_value, value)") {
		t.Fatalf("upsertFindingsBatchSQL unnest clause changed: %s", query)
	}
	if !strings.Contains(query, "SELECT batch.manifest_digest, batch.fingerprint, batch.redacted_value, batch.value, $5, $5 FROM") {
		t.Fatal("upsertFindingsBatchSQL does not supply the timestamp as $5 twice")
	}
	if !strings.Contains(query, "WHEN $6 AND") || !strings.HasSuffix(query, "RETURNING id, manifest_digest, fingerprint") {
		t.Fatal("upsertFindingsBatchSQL raw-secret flag or RETURNING clause changed")
	}
	highest := 0
	for _, match := range regexp.MustCompile(`\$([0-9]+)`).FindAllStringSubmatch(query, -1) {
		if value, _ := strconv.Atoi(match[1]); value > highest {
			highest = value
		}
	}
	if highest != 6 {
		t.Fatalf("upsertFindingsBatchSQL uses %d parameters, want 6", highest)
	}
}
