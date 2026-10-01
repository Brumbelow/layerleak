package layers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"

	"github.com/brumbelow/layerleak/v3/internal/limits"
)

// NestedPathSeparator joins the path of an archive stored in a layer with the
// path of an entry inside it: `outer/path!inner/path`. Nested entries are
// scanned one level deep; an archive inside a nested archive is never opened.
const NestedPathSeparator = "!"

// NestedSkipReason classifies why a nested archive, or some of its entries,
// was not expanded. Every reason is a bounded skip: the scan continues, the
// outer file keeps its own classification and the skip is reported.
type NestedSkipReason string

const (
	// NestedSkipOversize: the archive itself is larger than the nested byte limit.
	NestedSkipOversize NestedSkipReason = "oversize"
	// NestedSkipBytesLimit: decompressed bytes reached the nested byte limit.
	NestedSkipBytesLimit NestedSkipReason = "bytes_limit"
	// NestedSkipEntriesLimit: the archive has more entries than the nested
	// entry limit. A gzip or tar stream stops at the limit and keeps the
	// entries before it; a zip, whose directory would be parsed in full
	// first, is refused whole and Observed is the count its directory holds.
	NestedSkipEntriesLimit NestedSkipReason = "entries_limit"
	// NestedSkipLayerBudget: the layer or image byte/entry budget left no room.
	NestedSkipLayerBudget NestedSkipReason = "layer_budget"
	// NestedSkipRetainedBytes: keeping the expanded text would exceed the retained-bytes limit.
	NestedSkipRetainedBytes NestedSkipReason = "retained_bytes"
	// NestedSkipMalformed: the archive, or Observed entries of it, could not be decoded.
	NestedSkipMalformed NestedSkipReason = "malformed"
	// NestedSkipEncrypted: Observed entries are encrypted.
	NestedSkipEncrypted NestedSkipReason = "encrypted"
	// NestedSkipUnsupportedMethod: Observed entries use a compression method the reader lacks.
	NestedSkipUnsupportedMethod NestedSkipReason = "unsupported_method"
	// NestedSkipUnsafeEntries: Observed entries have unsafe paths (absolute, traversal, NUL, too long).
	NestedSkipUnsafeEntries NestedSkipReason = "unsafe_entries"
	// NestedSkipOversizeEntries: Observed entries exceed the per-file limit.
	NestedSkipOversizeEntries NestedSkipReason = "oversize_entries"
	// NestedSkipDepth: Observed entries are archives themselves and stay closed.
	NestedSkipDepth NestedSkipReason = "depth"
)

// NestedSkip reports one bounded skip while expanding the archive at Path in
// LayerDigest. Observed counts entries (or bytes, for Oversize) and Limit is
// the bound that applied, when one did.
type NestedSkip struct {
	Path        string
	LayerDigest string
	Reason      NestedSkipReason
	Observed    int64
	Limit       int64
}

// maxNestedSkipRecords bounds the skip records a replay keeps; later skips are
// counted in Coverage.NestedSkipsDropped so the report stays bounded.
const maxNestedSkipRecords = 256

// nestedArchiveKind sniffs the magic bytes that start a zip-family archive
// (.zip, .jar, .war, .whl, .egg), a gzip member or a POSIX/GNU tar archive.
func nestedArchiveKind(content []byte) string {
	switch {
	case len(content) >= 4 && content[0] == 'P' && content[1] == 'K' && content[2] == 0x03 && content[3] == 0x04:
		return "zip"
	case len(content) >= 2 && content[0] == 0x1f && content[1] == 0x8b:
		return "gzip"
	case len(content) >= 263 && (string(content[257:262]) == "ustar"):
		return "tar"
	}
	return ""
}

// nestedExpander expands the archives of one layer within the nested bounds
// and the layer's share of the image budgets.
type nestedExpander struct {
	options     ReplayOptions
	layerDigest string
	// Remaining per-layer allowances derived from MaxLayerBytes/MaxLayerEntries
	// and the image aggregates: nested expansion never fails a layer, it stops
	// when the allowance is spent.
	layerBytes   int64
	layerEntries int64
	imageBytes   int64
	imageEntries int64

	archivesExpanded int
	entriesScanned   int
	entriesSeen      int
	bytesExpanded    int64
	skips            []NestedSkip
	skipsDropped     int
	flushed          bool
}

// newNestedExpander prepares the per-layer expander, or returns nil when
// nested expansion is disabled (MaxNestedArchiveBytes 0).
func newNestedExpander(layerDigest string, options ReplayOptions, coverage Coverage) *nestedExpander {
	if options.MaxNestedArchiveBytes <= 0 {
		return nil
	}
	remaining := func(limit, used int64) int64 {
		if limit <= 0 {
			return math.MaxInt64
		}
		if used >= limit {
			return 0
		}
		return limit - used
	}
	return &nestedExpander{
		options:      options,
		layerDigest:  layerDigest,
		layerBytes:   effectiveLimit(options.MaxLayerBytes),
		layerEntries: effectiveLimit(int64(options.MaxLayerEntries)),
		imageBytes:   remaining(options.MaxTotalBytes, coverage.NestedBytesExpanded),
		imageEntries: remaining(int64(options.MaxTotalEntries), int64(coverage.NestedEntriesSeen)),
	}
}

// isCandidate reports whether a regular file of the given size with the given
// first bytes should be buffered for expansion.
func (e *nestedExpander) isCandidate(prefix []byte) bool {
	return e != nil && nestedArchiveKind(prefix) != ""
}

func (e *nestedExpander) skip(outerPath string, reason NestedSkipReason, observed, limit int64) {
	if len(e.skips) >= maxNestedSkipRecords {
		e.skipsDropped++
		return
	}
	e.skips = append(e.skips, NestedSkip{Path: outerPath, LayerDigest: e.layerDigest, Reason: reason, Observed: observed, Limit: limit})
}

// byteAllowance is the number of decompressed bytes the next archive may
// produce, and whether that bound is the nested limit itself (as opposed to
// what the layer or image budget has left).
func (e *nestedExpander) byteAllowance() (int64, bool) {
	allowance := e.options.MaxNestedArchiveBytes
	ownLimit := true
	for _, remaining := range []int64{e.layerBytes, e.imageBytes} {
		if remaining < allowance {
			allowance, ownLimit = remaining, false
		}
	}
	return allowance, ownLimit
}

func (e *nestedExpander) entryAllowance() (int64, bool) {
	allowance := effectiveLimit(int64(e.options.MaxNestedArchiveEntries))
	ownLimit := true
	for _, remaining := range []int64{e.layerEntries, e.imageEntries} {
		if remaining < allowance {
			allowance, ownLimit = remaining, false
		}
	}
	return allowance, ownLimit
}

// nestedEntry is one regular file read out of a nested archive.
type nestedEntry struct {
	name    string
	content []byte
}

// archiveWalk accumulates the outcome of reading one archive's entries.
type archiveWalk struct {
	expander       *nestedExpander
	outerPath      string
	byteAllowance  int64
	bytesOwnLimit  bool
	entryAllowance int64
	entryOwnLimit  bool
	bytesRead      int64
	entries        int64
	entriesSeen    int64
	files          []nestedEntry
	stopped        NestedSkipReason
	stopLimit      int64
	// refused is set when the archive was turned away whole, before any of
	// it was parsed, because its directory declares more entries than the
	// allowance; entriesSeen then holds the declared count.
	refused     bool
	malformed   int64
	encrypted   int64
	unsupported int64
	unsafe      int64
	oversize    int64
}

func (e *nestedExpander) newWalk(outerPath string) *archiveWalk {
	walk := &archiveWalk{expander: e, outerPath: outerPath}
	walk.byteAllowance, walk.bytesOwnLimit = e.byteAllowance()
	walk.entryAllowance, walk.entryOwnLimit = e.entryAllowance()
	return walk
}

// admitEntry charges one archive entry against the entry allowance. It
// returns false once the allowance is spent; the walk then stops.
func (w *archiveWalk) admitEntry() bool {
	w.entriesSeen++
	if w.entries >= w.entryAllowance {
		if w.entryOwnLimit {
			w.stopped, w.stopLimit = NestedSkipEntriesLimit, w.entryAllowance
		} else {
			w.stopped, w.stopLimit = NestedSkipLayerBudget, w.entryAllowance
		}
		return false
	}
	w.entries++
	return true
}

// refuseEntries turns the whole archive away before it is parsed: its
// directory holds observed entries, more than the entry allowance admits.
func (w *archiveWalk) refuseEntries(observed int64) {
	w.refused = true
	w.entriesSeen = observed
	if w.entryOwnLimit {
		w.stopped, w.stopLimit = NestedSkipEntriesLimit, w.entryAllowance
	} else {
		w.stopped, w.stopLimit = NestedSkipLayerBudget, w.entryAllowance
	}
}

// readEntry reads one entry's content without trusting any declared size:
// at most MaxFileBytes+1 bytes and never beyond the archive's byte allowance.
// The boolean is false when the walk must stop (byte allowance spent).
func (w *archiveWalk) readEntry(reader io.Reader) ([]byte, bool, error) {
	remaining := w.byteAllowance - w.bytesRead
	if remaining <= 0 {
		w.stopBytes()
		return nil, false, nil
	}
	maxFile := w.expander.options.MaxFileBytes
	limit := limits.OverflowProbeLimit(maxFile)
	if remaining < limit {
		limit = limits.OverflowProbeLimit(remaining)
	}
	content, err := io.ReadAll(io.LimitReader(reader, limit))
	w.bytesRead += int64(len(content))
	if w.bytesRead > w.byteAllowance {
		w.stopBytes()
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if int64(len(content)) > maxFile {
		w.oversize++
		// Drain the rest of the entry only within the byte allowance so an
		// entry lying about its size cannot make the reader run unbounded.
		drained, _ := io.Copy(io.Discard, io.LimitReader(reader, limits.OverflowProbeLimit(w.byteAllowance-w.bytesRead)))
		w.bytesRead += drained
		if w.bytesRead > w.byteAllowance {
			w.stopBytes()
			return nil, false, nil
		}
		return nil, true, nil
	}
	return content, true, nil
}

func (w *archiveWalk) stopBytes() {
	if w.bytesOwnLimit {
		w.stopped, w.stopLimit = NestedSkipBytesLimit, w.byteAllowance
	} else {
		w.stopped, w.stopLimit = NestedSkipLayerBudget, w.byteAllowance
	}
}

// safeInnerPath normalises an entry name with the same rules as layer entries
// (no absolute paths, parent traversal, NUL bytes, backslashes or over-long
// names). The boolean is false for a root entry, which carries nothing.
func (w *archiveWalk) safeInnerPath(name string) (string, bool) {
	cleaned, err := normalizePath(name)
	if err != nil {
		if !errors.Is(err, errRootEntry) {
			w.unsafe++
		}
		return "", false
	}
	return cleaned, true
}

// expand buffers nothing itself: content is the whole outer file. It returns
// the nested artifacts (text entries, and non-text entries the keep filter
// selects) in archive order and records the skips and counters.
func (e *nestedExpander) expand(outerPath string, content []byte) []Artifact {
	walk := e.newWalk(outerPath)
	switch nestedArchiveKind(content) {
	case "zip":
		walk.readZip(content)
	case "gzip":
		walk.readGzip(outerPath, content)
	case "tar":
		walk.readTar(bytes.NewReader(content))
	default:
		return nil
	}
	return e.finish(walk)
}

func (w *archiveWalk) readZip(content []byte) {
	// archive/zip materialises every central directory header before the
	// first entry can be examined, so the entry bound is applied to the
	// directory's own account of itself first: an archive with more entries
	// than the allowance is refused whole rather than parsed and then cut.
	if entries, ok := zipDirectoryEntries(content); ok && entries > w.entryAllowance {
		w.refuseEntries(entries)
		return
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		w.malformed++
		return
	}
	for _, file := range reader.File {
		if !w.admitEntry() {
			return
		}
		mode := file.Mode()
		if strings.HasSuffix(file.Name, "/") || mode.IsDir() {
			continue
		}
		if mode&fs.ModeSymlink != 0 || !mode.IsRegular() {
			// Symlinks are never followed and device or socket entries carry
			// nothing to scan; this mirrors the layer rules.
			continue
		}
		if file.Flags&0x1 != 0 || file.Flags&0x40 != 0 {
			w.encrypted++
			continue
		}
		name, ok := w.safeInnerPath(file.Name)
		if !ok {
			continue
		}
		entryReader, err := file.Open()
		if err != nil {
			if errors.Is(err, zip.ErrAlgorithm) {
				w.unsupported++
			} else {
				w.malformed++
			}
			continue
		}
		data, proceed, err := w.readEntry(entryReader)
		_ = entryReader.Close()
		if !proceed {
			return
		}
		if err != nil {
			w.malformed++
			continue
		}
		if data != nil {
			w.files = append(w.files, nestedEntry{name: name, content: data})
		}
	}
}

// readGzip decompresses a gzip member (bounded by the byte allowance). A tar
// archive inside it is walked; anything else is one file named by the gzip
// header or by the outer name without its .gz/.tgz suffix.
func (w *archiveWalk) readGzip(outerPath string, content []byte) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		w.malformed++
		return
	}
	defer func() { _ = gzipReader.Close() }()
	limit := limits.OverflowProbeLimit(w.byteAllowance)
	decompressed, err := io.ReadAll(io.LimitReader(gzipReader, limit))
	if int64(len(decompressed)) > w.byteAllowance {
		w.bytesRead = w.byteAllowance + 1
		w.stopBytes()
		return
	}
	if err != nil {
		w.malformed++
		return
	}
	if nestedArchiveKind(decompressed) == "tar" {
		w.readTar(bytes.NewReader(decompressed))
		return
	}
	if !w.admitEntry() {
		return
	}
	name := gzipMemberName(outerPath, gzipReader.Name)
	data, proceed, err := w.readEntry(bytes.NewReader(decompressed))
	if !proceed || err != nil {
		return
	}
	if data != nil {
		w.files = append(w.files, nestedEntry{name: name, content: data})
	}
}

// gzipMemberName picks the inner name of a single gzipped file: the header
// name when it is a safe relative path, else the outer base name without its
// compression suffix, else "content".
func gzipMemberName(outerPath, headerName string) string {
	if headerName != "" {
		if cleaned, err := normalizePath(headerName); err == nil {
			return cleaned
		}
	}
	base := path.Base(outerPath)
	for _, suffix := range []string{".tgz", ".gz", ".GZ"} {
		if strings.HasSuffix(base, suffix) && len(base) > len(suffix) {
			return strings.TrimSuffix(base, suffix)
		}
	}
	return "content"
}

func (w *archiveWalk) readTar(reader io.Reader) {
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			w.malformed++
			return
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if !w.admitEntry() {
			return
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
		default:
			// Directories, symlinks, hardlinks and special files are not
			// followed or recorded inside a nested archive.
			continue
		}
		name, ok := w.safeInnerPath(header.Name)
		if !ok {
			continue
		}
		data, proceed, err := w.readEntry(tarReader)
		if !proceed {
			return
		}
		if err != nil {
			w.malformed++
			return
		}
		if data != nil {
			w.files = append(w.files, nestedEntry{name: name, content: data})
		}
	}
}

// finish classifies the entries that were read, charges the layer and image
// allowances and records the skips. Entries that are archives themselves are
// counted and left closed.
func (e *nestedExpander) finish(walk *archiveWalk) []Artifact {
	e.layerBytes = saturatingSub(e.layerBytes, walk.bytesRead)
	e.imageBytes = saturatingSub(e.imageBytes, walk.bytesRead)
	e.layerEntries = saturatingSub(e.layerEntries, walk.entries)
	e.imageEntries = saturatingSub(e.imageEntries, walk.entries)
	e.bytesExpanded += walk.bytesRead
	e.entriesSeen += int(walk.entries)

	nested := make([]Artifact, 0, len(walk.files))
	var depth int64
	for _, file := range walk.files {
		innerPath := walk.outerPath + NestedPathSeparator + file.name
		if nestedArchiveKind(file.content) != "" {
			depth++
			if e.options.NestedKeepPath != nil && e.options.NestedKeepPath(innerPath) {
				nested = append(nested, Artifact{Path: innerPath, LayerDigest: e.layerDigest, Type: ArtifactTypeRegularFile, Size: int64(len(file.content)), ContentClass: ContentClassBinaryNUL})
			}
			continue
		}
		artifact := classifyRegularContent(innerPath, e.layerDigest, file.content, int64(len(file.content)), e.options.MaxFileBytes)
		e.entriesScanned++
		if !artifact.Scannable && (e.options.NestedKeepPath == nil || !e.options.NestedKeepPath(innerPath)) {
			continue
		}
		nested = append(nested, artifact)
	}

	if walk.stopped != "" {
		e.skip(walk.outerPath, walk.stopped, walk.entriesSeen, walk.stopLimit)
	}
	for _, record := range []struct {
		reason NestedSkipReason
		count  int64
	}{
		{NestedSkipMalformed, walk.malformed},
		{NestedSkipEncrypted, walk.encrypted},
		{NestedSkipUnsupportedMethod, walk.unsupported},
		{NestedSkipUnsafeEntries, walk.unsafe},
		{NestedSkipOversizeEntries, walk.oversize},
		{NestedSkipDepth, depth},
	} {
		if record.count > 0 {
			limit := int64(0)
			if record.reason == NestedSkipOversizeEntries {
				limit = e.options.MaxFileBytes
			}
			e.skip(walk.outerPath, record.reason, record.count, limit)
		}
	}
	if walk.refused || (walk.malformed > 0 && len(walk.files) == 0 && walk.entriesSeen == 0) {
		// Nothing was read: the archive is reported but not counted as
		// expanded.
		return nil
	}
	e.archivesExpanded++
	return nested
}

func saturatingSub(value, amount int64) int64 {
	if value == math.MaxInt64 {
		return value
	}
	if amount >= value {
		return 0
	}
	return value - amount
}

// nestedRetainedBytes is the retention charge of the expanded entries kept on
// an artifact: each is accounted like a final artifact of its own.
func nestedRetainedBytes(nested []Artifact) int64 {
	var total int64
	for _, artifact := range nested {
		total += retainedFinalArtifactBaseBytes(artifact.Path, "") + int64(len(artifact.Content))
	}
	return total
}
