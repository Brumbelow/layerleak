package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/lib/pq"
)

// findingBatchSize bounds the rows per multi-row upsert. 500 keeps every
// statement well under PostgreSQL's parameter and packet comfort zone while
// turning the 20,000 round trips of a 10,000-finding scan into about 40.
const findingBatchSize = 500

type findingKey struct {
	manifestDigest string
	fingerprint    string
}

type findingRow struct {
	key           findingKey
	redactedValue string
	value         string
}

// occurrenceIdentity mirrors the finding_occurrences_identity_key constraint:
// PostgreSQL rejects a multi-row INSERT ... ON CONFLICT DO UPDATE that touches
// the same conflict key twice, so rows are collapsed on it before the batch.
type occurrenceIdentity struct {
	key                 findingKey
	detectorName        string
	confidence          string
	sourceType          string
	platformOS          string
	platformArch        string
	platformVariant     string
	filePath            string
	layerDigest         string
	sourceKey           string
	contextSnippet      string
	sourceLocation      string
	matchStart          int
	matchEnd            int
	presentInFinalImage bool
}

type occurrenceRow struct {
	identity          occurrenceIdentity
	disposition       string
	dispositionReason string
	lineNumber        int
	rawSnippet        string
}

// collapseFindings keeps one row per (manifest_digest, fingerprint) in first
// appearance order. The last item in sorted order supplies the redacted and
// raw values, which is what the serial upsert produced: every row of one scan
// shares last_seen_at, so each later upsert overwrote the earlier one.
func collapseFindings(items []findings.DetailedFinding, persistRawSecrets bool) []findingRow {
	rows := make([]findingRow, 0, len(items))
	positions := make(map[findingKey]int, len(items))
	for _, item := range items {
		row := findingRow{
			key:           findingKeyOf(item),
			redactedValue: item.RedactedValue,
			value:         persistedValue(item, persistRawSecrets),
		}
		if position, ok := positions[row.key]; ok {
			rows[position] = row
			continue
		}
		positions[row.key] = len(rows)
		rows = append(rows, row)
	}
	return rows
}

// collapseOccurrences keeps one row per database identity in first appearance
// order; the last item in sorted order supplies the mutable columns
// (disposition, reason, line number, raw snippet), as the serial upsert did.
func collapseOccurrences(items []findings.DetailedFinding, persistRawSecrets bool) []occurrenceRow {
	rows := make([]occurrenceRow, 0, len(items))
	positions := make(map[occurrenceIdentity]int, len(items))
	for _, item := range items {
		row := occurrenceRow{
			identity: occurrenceIdentity{
				key:                 findingKeyOf(item),
				detectorName:        item.DetectorName,
				confidence:          item.Confidence,
				sourceType:          string(item.SourceType),
				platformOS:          item.Platform.OS,
				platformArch:        item.Platform.Architecture,
				platformVariant:     item.Platform.Variant,
				filePath:            item.FilePath,
				layerDigest:         item.LayerDigest,
				sourceKey:           item.Key,
				contextSnippet:      item.ContextSnippet,
				sourceLocation:      item.SourceLocation,
				matchStart:          item.MatchStart,
				matchEnd:            item.MatchEnd,
				presentInFinalImage: item.PresentInFinalImage,
			},
			disposition:       string(item.Disposition),
			dispositionReason: string(item.DispositionReason),
			lineNumber:        item.LineNumber,
			rawSnippet:        persistedRawSnippet(item, persistRawSecrets),
		}
		if position, ok := positions[row.identity]; ok {
			rows[position] = row
			continue
		}
		positions[row.identity] = len(rows)
		rows = append(rows, row)
	}
	return rows
}

func findingKeyOf(item findings.DetailedFinding) findingKey {
	return findingKey{
		manifestDigest: strings.TrimSpace(item.ManifestDigest),
		fingerprint:    strings.TrimSpace(item.Fingerprint),
	}
}

const upsertFindingsBatchSQL = `
	INSERT INTO findings (
		manifest_digest,
		fingerprint,
		redacted_value,
		value,
		first_seen_at,
		last_seen_at
	)
	SELECT batch.manifest_digest, batch.fingerprint, batch.redacted_value, batch.value, $5, $5
	FROM unnest($1::text[], $2::text[], $3::text[], $4::text[])
		AS batch(manifest_digest, fingerprint, redacted_value, value)
	ON CONFLICT (manifest_digest, fingerprint)
	DO UPDATE SET
		redacted_value = CASE
			WHEN EXCLUDED.last_seen_at >= findings.last_seen_at THEN EXCLUDED.redacted_value
			ELSE findings.redacted_value
		END,
		value = CASE
			WHEN $6 AND EXCLUDED.last_seen_at >= findings.last_seen_at THEN EXCLUDED.value
			ELSE findings.value
		END,
		first_seen_at = LEAST(findings.first_seen_at, EXCLUDED.first_seen_at),
		last_seen_at = GREATEST(findings.last_seen_at, EXCLUDED.last_seen_at)
	RETURNING id, manifest_digest, fingerprint
`

// upsertFindingsBatch writes the collapsed findings in sorted chunks and
// returns the database id of every (manifest_digest, fingerprint).
func upsertFindingsBatch(ctx context.Context, tx *sql.Tx, rows []findingRow, scannedAt time.Time, persistRawSecrets bool) (map[findingKey]int64, error) {
	ids := make(map[findingKey]int64, len(rows))
	for start := 0; start < len(rows); start += findingBatchSize {
		chunk := rows[start:min(start+findingBatchSize, len(rows))]
		manifestDigests := make([]string, len(chunk))
		fingerprints := make([]string, len(chunk))
		redactedValues := make([]string, len(chunk))
		values := make([]string, len(chunk))
		for index, row := range chunk {
			manifestDigests[index] = row.key.manifestDigest
			fingerprints[index] = row.key.fingerprint
			redactedValues[index] = row.redactedValue
			values[index] = row.value
		}
		if err := scanFindingIDs(ctx, tx, ids, pq.Array(manifestDigests), pq.Array(fingerprints), pq.Array(redactedValues), pq.Array(values), scannedAt, persistRawSecrets); err != nil {
			return nil, fmt.Errorf("upsert findings %d-%d of %d: %w", start+1, start+len(chunk), len(rows), err)
		}
	}
	if len(ids) != len(rows) {
		return nil, fmt.Errorf("upsert findings: database returned %d ids for %d rows", len(ids), len(rows))
	}
	return ids, nil
}

func scanFindingIDs(ctx context.Context, tx *sql.Tx, ids map[findingKey]int64, args ...any) error {
	result, err := tx.QueryContext(ctx, upsertFindingsBatchSQL, args...)
	if err != nil {
		return err
	}
	defer func() { _ = result.Close() }()
	for result.Next() {
		var id int64
		var key findingKey
		if err := result.Scan(&id, &key.manifestDigest, &key.fingerprint); err != nil {
			return err
		}
		ids[key] = id
	}
	return result.Err()
}

const upsertFindingOccurrencesBatchSQL = `
	INSERT INTO finding_occurrences (
		finding_id,
		detector_name,
		confidence,
		disposition,
		disposition_reason,
		source_type,
		platform_os,
		platform_architecture,
		platform_variant,
		file_path,
		layer_digest,
		source_key,
		line_number,
		context_snippet,
		raw_snippet,
		source_location,
		match_start,
		match_end,
		present_in_final_image,
		first_seen_at,
		last_seen_at
	)
	SELECT batch.*, $20, $20
	FROM unnest(
		$1::bigint[],
		$2::text[],
		$3::text[],
		$4::text[],
		$5::text[],
		$6::text[],
		$7::text[],
		$8::text[],
		$9::text[],
		$10::text[],
		$11::text[],
		$12::text[],
		$13::integer[],
		$14::text[],
		$15::text[],
		$16::text[],
		$17::integer[],
		$18::integer[],
		$19::boolean[]
	) AS batch(
		finding_id,
		detector_name,
		confidence,
		disposition,
		disposition_reason,
		source_type,
		platform_os,
		platform_architecture,
		platform_variant,
		file_path,
		layer_digest,
		source_key,
		line_number,
		context_snippet,
		raw_snippet,
		source_location,
		match_start,
		match_end,
		present_in_final_image
	)
	ON CONFLICT (
		finding_id,
		detector_name,
		confidence,
		source_type,
		platform_os,
		platform_architecture,
		platform_variant,
		file_path,
		layer_digest,
		source_key,
		context_snippet,
		source_location,
		match_start,
		match_end,
		present_in_final_image
	)
	DO UPDATE SET
		disposition = CASE
			WHEN EXCLUDED.last_seen_at >= finding_occurrences.last_seen_at THEN EXCLUDED.disposition
			ELSE finding_occurrences.disposition
		END,
		disposition_reason = CASE
			WHEN EXCLUDED.last_seen_at >= finding_occurrences.last_seen_at THEN EXCLUDED.disposition_reason
			ELSE finding_occurrences.disposition_reason
		END,
		line_number = CASE
			WHEN EXCLUDED.last_seen_at >= finding_occurrences.last_seen_at THEN EXCLUDED.line_number
			ELSE finding_occurrences.line_number
		END,
		raw_snippet = CASE
			WHEN $21 AND EXCLUDED.last_seen_at >= finding_occurrences.last_seen_at THEN EXCLUDED.raw_snippet
			ELSE finding_occurrences.raw_snippet
		END,
		first_seen_at = LEAST(finding_occurrences.first_seen_at, EXCLUDED.first_seen_at),
		last_seen_at = GREATEST(finding_occurrences.last_seen_at, EXCLUDED.last_seen_at)
`

// upsertFindingOccurrencesBatch writes the collapsed occurrences in sorted
// chunks, resolving each row's finding_id from the ids the findings batch
// returned.
func upsertFindingOccurrencesBatch(ctx context.Context, tx *sql.Tx, rows []occurrenceRow, ids map[findingKey]int64, scannedAt time.Time, persistRawSecrets bool) error {
	for start := 0; start < len(rows); start += findingBatchSize {
		chunk := rows[start:min(start+findingBatchSize, len(rows))]
		batch := newOccurrenceBatch(len(chunk))
		for index, row := range chunk {
			findingID, ok := ids[row.identity.key]
			if !ok {
				return fmt.Errorf("upsert finding occurrences: no finding id for %s/%s", row.identity.key.manifestDigest, row.identity.key.fingerprint)
			}
			batch.set(index, findingID, row)
		}
		if _, err := tx.ExecContext(ctx, upsertFindingOccurrencesBatchSQL, batch.args(scannedAt, persistRawSecrets)...); err != nil {
			return fmt.Errorf("upsert finding occurrences %d-%d of %d: %w", start+1, start+len(chunk), len(rows), err)
		}
	}
	return nil
}

type occurrenceBatch struct {
	findingIDs           []int64
	detectorNames        []string
	confidences          []string
	dispositions         []string
	dispositionReasons   []string
	sourceTypes          []string
	platformOSes         []string
	platformArchs        []string
	platformVariants     []string
	filePaths            []string
	layerDigests         []string
	sourceKeys           []string
	lineNumbers          []int64
	contextSnippets      []string
	rawSnippets          []string
	sourceLocations      []string
	matchStarts          []int64
	matchEnds            []int64
	presentInFinalImages []bool
}

func newOccurrenceBatch(size int) *occurrenceBatch {
	return &occurrenceBatch{
		findingIDs:           make([]int64, size),
		detectorNames:        make([]string, size),
		confidences:          make([]string, size),
		dispositions:         make([]string, size),
		dispositionReasons:   make([]string, size),
		sourceTypes:          make([]string, size),
		platformOSes:         make([]string, size),
		platformArchs:        make([]string, size),
		platformVariants:     make([]string, size),
		filePaths:            make([]string, size),
		layerDigests:         make([]string, size),
		sourceKeys:           make([]string, size),
		lineNumbers:          make([]int64, size),
		contextSnippets:      make([]string, size),
		rawSnippets:          make([]string, size),
		sourceLocations:      make([]string, size),
		matchStarts:          make([]int64, size),
		matchEnds:            make([]int64, size),
		presentInFinalImages: make([]bool, size),
	}
}

func (b *occurrenceBatch) set(index int, findingID int64, row occurrenceRow) {
	b.findingIDs[index] = findingID
	b.detectorNames[index] = row.identity.detectorName
	b.confidences[index] = row.identity.confidence
	b.dispositions[index] = row.disposition
	b.dispositionReasons[index] = row.dispositionReason
	b.sourceTypes[index] = row.identity.sourceType
	b.platformOSes[index] = row.identity.platformOS
	b.platformArchs[index] = row.identity.platformArch
	b.platformVariants[index] = row.identity.platformVariant
	b.filePaths[index] = row.identity.filePath
	b.layerDigests[index] = row.identity.layerDigest
	b.sourceKeys[index] = row.identity.sourceKey
	b.lineNumbers[index] = int64(row.lineNumber)
	b.contextSnippets[index] = row.identity.contextSnippet
	b.rawSnippets[index] = row.rawSnippet
	b.sourceLocations[index] = row.identity.sourceLocation
	b.matchStarts[index] = int64(row.identity.matchStart)
	b.matchEnds[index] = int64(row.identity.matchEnd)
	b.presentInFinalImages[index] = row.identity.presentInFinalImage
}

// args orders the parameters exactly as upsertFindingOccurrencesBatchSQL
// numbers them: $1..$19 are the unnest arrays, $20 the timestamp and $21 the
// raw-secret flag.
func (b *occurrenceBatch) args(scannedAt time.Time, persistRawSecrets bool) []any {
	return []any{
		pq.Array(b.findingIDs),
		pq.Array(b.detectorNames),
		pq.Array(b.confidences),
		pq.Array(b.dispositions),
		pq.Array(b.dispositionReasons),
		pq.Array(b.sourceTypes),
		pq.Array(b.platformOSes),
		pq.Array(b.platformArchs),
		pq.Array(b.platformVariants),
		pq.Array(b.filePaths),
		pq.Array(b.layerDigests),
		pq.Array(b.sourceKeys),
		pq.Array(b.lineNumbers),
		pq.Array(b.contextSnippets),
		pq.Array(b.rawSnippets),
		pq.Array(b.sourceLocations),
		pq.Array(b.matchStarts),
		pq.Array(b.matchEnds),
		pq.Array(b.presentInFinalImages),
		scannedAt,
		persistRawSecrets,
	}
}
