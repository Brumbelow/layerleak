package layers

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/klauspost/compress/zstd"
)

type ArtifactType string

const (
	ArtifactTypeRegularFile ArtifactType = "regular"
	ArtifactTypeHardlink    ArtifactType = "hardlink"
	ArtifactTypeSymlink     ArtifactType = "symlink"
	ArtifactTypeOther       ArtifactType = "other"
)

type ContentClass string

const (
	ContentClassText               ContentClass = "text"
	ContentClassOversize           ContentClass = "oversize"
	ContentClassBinaryELF          ContentClass = "binary_elf"
	ContentClassBinarySharedObject ContentClass = "binary_shared_object"
	ContentClassBinaryNUL          ContentClass = "binary_nul"
	ContentClassBinaryLowPrintable ContentClass = "binary_low_printable"

	maxArchivePathBytes = 4096

	// Retention accounting includes conservative per-entry storage for artifact
	// records and the maps/slices that keep archive metadata live.
	retainedArtifactMetadataBytes   = 160
	retainedMapEntryMetadataBytes   = 32
	retainedSliceEntryMetadataBytes = 32
	retainedPathIndexMetadataBytes  = 256

	// zstdDecoderWindowLimit bounds the zstd history window and therefore the
	// memory a single frame header can make the decoder allocate. It is fixed
	// on purpose: MAX_LAYER_BYTES bounds stream length, not decoder memory, and
	// real layers use 8 MiB windows (the zstd CLI refuses >128 MiB by default).
	// Streaming decode does not cap the decompressed size, so larger layers
	// still decode as long as their window fits.
	zstdDecoderWindowLimit = 128 << 20
)

type Artifact struct {
	Path                 string
	LayerDigest          string
	DeletedByLayerDigest string
	Type                 ArtifactType
	Linkname             string
	Content              []byte
	Size                 int64
	ContentClass         ContentClass
	Scannable            bool
	// SourceEncoding names the stored encoding of a text file whose Content
	// was transcoded to UTF-8 (UTF-16 with or without a byte-order mark).
	// Offsets and line numbers of findings refer to the transcoded Content.
	SourceEncoding TextEncoding
	// Nested holds the entries expanded one level deep out of an archive
	// (zip family, gzip, tar) stored at Path. Each has the provenance path
	// `Path!inner/path`, its own content and classification, and shares the
	// outer artifact's fate: it is deleted or overwritten with it.
	Nested []Artifact
}

type ReplayResult struct {
	FinalFiles       []Artifact
	DeletedArtifacts []Artifact
	Coverage         Coverage
	// NestedSkips lists, in replay order, every bounded skip while expanding
	// nested archives (capped at maxNestedSkipRecords; the rest are counted in
	// Coverage.NestedSkipsDropped).
	NestedSkips []NestedSkip
}

type ReplayOptions struct {
	MaxFileBytes     int64
	MaxLayerBytes    int64
	MaxLayerEntries  int
	MaxTotalBytes    int64
	MaxTotalEntries  int
	MaxRetainedBytes int64
	// MaxNestedArchiveBytes bounds both the stored size of an archive that is
	// buffered for one-level expansion and the decompressed bytes read out of
	// it. 0 disables nested expansion.
	MaxNestedArchiveBytes int64
	// MaxNestedArchiveEntries bounds the entries examined per nested archive;
	// 0 leaves only the layer and image entry budgets.
	MaxNestedArchiveEntries int
	// NestedKeepPath decides whether a nested entry that is not scannable text
	// (binary, oversize or itself an archive) is kept as a path-only artifact.
	// Nil keeps none; the scanner passes its path-only detectors.
	NestedKeepPath func(path string) bool
}

type Coverage struct {
	LayersSeen           int
	LayersCompleted      int
	FilesSeen            int
	FilesScanned         int
	FilesSkippedOversize int
	FilesExcludedBinary  int
	EntriesSkippedUnsafe int
	// FilesTranscodedUTF16 counts scanned files (and hardlinks to them) whose
	// UTF-16 content was transcoded to UTF-8 before detection.
	FilesTranscodedUTF16 int
	ExpandedBytes        int64
	RetainedBytes        int64
	// NestedArchivesExpanded counts archives stored in layers that were opened
	// one level deep; NestedEntriesScanned counts the regular files inside them
	// that were classified (scanned by content or checked by path).
	NestedArchivesExpanded int
	NestedEntriesScanned   int
	// NestedEntriesSeen and NestedBytesExpanded are the image-wide charges of
	// nested expansion against the entry and byte budgets; NestedSkipsDropped
	// counts skip records beyond the retained maximum.
	NestedEntriesSeen   int
	NestedBytesExpanded int64
	NestedSkipsDropped  int
}

// UnsupportedLayerError reports a manifest that cannot be replayed because one
// of its layers is foreign/non-distributable or uses an unknown media type.
// It is an unsupported-platform outcome, never an integrity failure: the
// descriptors themselves are well formed.
type UnsupportedLayerError struct {
	Index     int
	Digest    string
	MediaType string
}

func (e *UnsupportedLayerError) Error() string {
	reason := "unsupported media type"
	if manifest.IsForeignLayerMediaType(e.MediaType) {
		reason = "non-distributable (foreign) media type"
	}
	return fmt.Sprintf("layer[%d] %s has %s %q and cannot be scanned", e.Index, strings.TrimSpace(e.Digest), reason, manifest.MediaTypeBase(e.MediaType))
}

// IsUnsupportedLayer reports whether err was caused by an unscannable layer.
func IsUnsupportedLayer(err error) bool {
	var target *UnsupportedLayerError
	return errors.As(err, &target)
}

// TrailingDataError reports bytes after the end of the compressed layer
// stream. The blob digest may well verify; the layer still fails closed (as
// containerd does) because the extra bytes are not part of the archive.
type TrailingDataError struct {
	Digest string
	Cause  error
}

func (e *TrailingDataError) Error() string {
	return fmt.Sprintf("layer %s has trailing data after the compressed stream: %v", strings.TrimSpace(e.Digest), e.Cause)
}

func (e *TrailingDataError) Unwrap() error {
	return e.Cause
}

// IsTrailingData reports whether err was caused by data after the stream.
func IsTrailingData(err error) bool {
	var target *TrailingDataError
	return errors.As(err, &target)
}

type BlobOpener interface {
	OpenLayer(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error)
}

type OpenFunc func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error)

func (f OpenFunc) OpenLayer(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
	return f(ctx, descriptor)
}

type State struct {
	final             map[string]Artifact
	deleted           []Artifact
	dirs              map[string]struct{}
	directoryChildren map[string]map[string]struct{}
	artifactChildren  map[string]map[string]struct{}
	entries           int
	coverage          Coverage
	nestedSkips       []NestedSkip
	// journal records the mutations of the layer being applied, nil between layers.
	journal *layerJournal
}

func NewState() *State {
	return &State{
		final:             make(map[string]Artifact),
		dirs:              make(map[string]struct{}),
		directoryChildren: make(map[string]map[string]struct{}),
		artifactChildren:  make(map[string]map[string]struct{}),
	}
}

func Replay(ctx context.Context, descriptors []manifest.Descriptor, options ReplayOptions, opener BlobOpener) (ReplayResult, error) {
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = 1 << 20
	}

	state := NewState()
	// Decide up front whether the whole manifest can be replayed so that no
	// blob is downloaded for an image whose later layers are unscannable.
	for index, descriptor := range descriptors {
		if !manifest.IsLayerMediaType(descriptor.MediaType) {
			return state.Result(), &UnsupportedLayerError{Index: index, Digest: descriptor.Digest, MediaType: descriptor.MediaType}
		}
	}
	for _, descriptor := range descriptors {
		if err := contextError(ctx); err != nil {
			return state.Result(), err
		}
		state.coverage.LayersSeen++

		stream, err := opener.OpenLayer(ctx, descriptor)
		if err != nil {
			return state.Result(), fmt.Errorf("open layer %s: %w", descriptor.Digest, err)
		}

		if err := state.applyLayer(ctx, descriptor, stream, options); err != nil {
			_ = stream.Close()
			return state.Result(), fmt.Errorf("apply layer %s: %w", descriptor.Digest, err)
		}
		if err := stream.Close(); err != nil {
			return state.Result(), fmt.Errorf("close layer %s: %w", descriptor.Digest, err)
		}
		state.coverage.LayersCompleted++
	}

	return state.Result(), nil
}

func (s *State) Result() ReplayResult {
	return ReplayResult{
		FinalFiles:       s.FinalFiles(),
		DeletedArtifacts: s.DeletedArtifacts(),
		Coverage:         s.coverage,
		NestedSkips:      append([]NestedSkip(nil), s.nestedSkips...),
	}
}

func (s *State) FinalFiles() []Artifact {
	files := make([]Artifact, 0, len(s.final))
	for _, artifact := range s.final {
		if artifact.Type == ArtifactTypeRegularFile || artifact.Type == ArtifactTypeHardlink {
			files = append(files, artifact)
		}
	}
	sortArtifacts(files)
	return files
}

func (s *State) DeletedArtifacts() []Artifact {
	artifacts := append([]Artifact(nil), s.deleted...)
	sortArtifacts(artifacts)
	return artifacts
}

func (s *State) applyLayer(ctx context.Context, descriptor manifest.Descriptor, blob io.Reader, options ReplayOptions) (returnErr error) {
	reader, cleanup, err := decompressLayer(descriptor.MediaType, blob)
	if err != nil {
		return err
	}
	defer cleanup()

	limitedReader := newLayerLimitReader(
		newContextReader(ctx, reader),
		descriptor.Digest,
		options.MaxLayerBytes,
		s.coverage.ExpandedBytes,
		options.MaxTotalBytes,
	)
	logicalBudget := newLogicalLayerBudget(
		descriptor.Digest,
		options.MaxLayerBytes,
		s.coverage.ExpandedBytes,
		options.MaxTotalBytes,
	)
	tarReader := tar.NewReader(limitedReader)
	retention := retentionBudget{maxBytes: options.MaxRetainedBytes}
	nested := newNestedExpander(descriptor.Digest, options, s.coverage)
	journal := s.beginLayer()
	committed := false
	defer func() {
		if committed {
			return
		}
		// A failed layer leaves the state exactly as it was before it: every
		// mutation is undone in reverse order and the retained-byte counter is
		// restored. The file, entry and nested-expansion counters are
		// observations of the failed layer and are kept.
		nested.flush(s)
		s.rollback(journal)
		s.coverage.ExpandedBytes = expandedBytesAfterLayer(journal.coverage.ExpandedBytes, limitedReader.readBytes, logicalBudget.bytes)
	}()
	currentPaths := journal.currentPaths
	whiteouts := make([]string, 0)
	opaqueDirectories := make([]string, 0)
	entryCount := 0
	for {
		if err := contextError(ctx); err != nil {
			return err
		}
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		// Sparse holes are synthesised by archive/tar without touching the
		// compressed stream, so the per-entry reader must observe ctx itself.
		entryReader := newContextReader(ctx, tarReader)
		if header.Typeflag == tar.TypeXGlobalHeader {
			// PAX global headers (git archive, tar --pax-option) describe the
			// entries that follow; they are never content and runtimes skip them.
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			continue
		}
		entryCount++
		if err := logicalBudget.add(header.Size); err != nil {
			return err
		}
		if options.MaxTotalEntries > 0 && s.entries+entryCount > options.MaxTotalEntries {
			return limits.NewExceeded(limits.Kind("image_entries"), int64(options.MaxTotalEntries), "image")
		}
		if options.MaxLayerEntries > 0 && entryCount > options.MaxLayerEntries {
			return limits.NewExceeded(limits.KindLayerEntries, int64(options.MaxLayerEntries), "layer "+descriptor.Digest)
		}

		entryPath, err := normalizePath(header.Name)
		if err != nil {
			if !errors.Is(err, errRootEntry) {
				// A `./` or `.` entry names the layer root itself (tar -C rootfs -c .
				// always emits one); it carries nothing to record and is not unsafe.
				s.coverage.EntriesSkippedUnsafe++
			}
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			continue
		}
		if err := validateLinkname(header.Linkname); err != nil {
			s.coverage.EntriesSkippedUnsafe++
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			continue
		}

		if isOpaqueWhiteout(entryPath) {
			directory := path.Dir(entryPath)
			if err := retention.retainTemporary(s, retainedSliceStringBytes(directory)); err != nil {
				return err
			}
			opaqueDirectories = append(opaqueDirectories, directory)
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			continue
		}
		if isWhiteout(entryPath) {
			target, targetErr := whiteoutTarget(entryPath)
			if targetErr != nil {
				s.coverage.EntriesSkippedUnsafe++
			} else {
				if err := retention.retainTemporary(s, retainedSliceStringBytes(target)); err != nil {
					return err
				}
				whiteouts = append(whiteouts, target)
			}
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			if err := s.preparePath(entryPath, true, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := s.addDirectory(entryPath, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(s, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			if err := s.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := s.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeSymlink,
				Linkname:     header.Linkname,
				ContentClass: "",
				Scannable:    false,
			}, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(s, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			linkTarget, err := normalizePath(header.Linkname)
			if err != nil {
				if !errors.Is(err, errRootEntry) {
					s.coverage.EntriesSkippedUnsafe++
				}
				continue
			}
			target, ok := s.final[linkTarget]
			if !ok {
				// A hardlink to a directory is invalid but harmless: runtimes
				// refuse it without failing the layer, so it is ignored rather
				// than counted as an unsafe entry that forces partial coverage.
				if _, isDirectory := s.dirs[linkTarget]; !isDirectory {
					s.coverage.EntriesSkippedUnsafe++
				}
				continue
			}
			// A hardlink is another name for its target. Links to regular files
			// become hardlink artifacts sharing the target's content and class;
			// links to symlinks or other artifacts take the target's type and are
			// neither files seen nor binary exclusions.
			linked := target
			linked.Path = entryPath
			linked.LayerDigest = descriptor.Digest
			isFile := target.Type == ArtifactTypeRegularFile || target.Type == ArtifactTypeHardlink
			if isFile {
				linked.Type = ArtifactTypeHardlink
				linked.Linkname = linkTarget
				s.coverage.FilesSeen++
			}
			if err := s.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := s.put(linked, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(s, currentPaths, entryPath, &retention); err != nil {
				return err
			}
			if !isFile {
				continue
			}
			if target.Scannable {
				s.coverage.FilesScanned++
				if target.SourceEncoding != "" {
					s.coverage.FilesTranscodedUTF16++
				}
			} else if target.ContentClass == ContentClassOversize {
				s.coverage.FilesSkippedOversize++
			} else {
				s.coverage.FilesExcludedBinary++
			}
		case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
			// archive/tar normalizes the legacy TypeRegA flag to TypeReg but keeps
			// the old-GNU sparse ('S') and GNU contiguous ('7') flags on regular
			// files; the entry reader already presents their logical content.
			s.coverage.FilesSeen++
			if header.Size <= options.MaxFileBytes {
				prospective := retainedFinalArtifactBaseBytes(entryPath, "") + header.Size
				if err := retention.ensure(s, prospective); err != nil {
					return err
				}
			}
			artifact, err := buildRegularArtifact(entryPath, descriptor.Digest, entryReader, header.Size, options, nested)
			if err != nil {
				return err
			}
			if len(artifact.Nested) > 0 {
				// Nested entries never fail a layer: when retaining them would
				// exceed the retained-bytes limit they are dropped and reported.
				if err := retention.ensure(s, retainedFinalArtifactBytes(artifact)); err != nil {
					nested.skip(entryPath, NestedSkipRetainedBytes, int64(len(artifact.Nested)), options.MaxRetainedBytes)
					artifact.Nested = nil
				}
			}
			if err := s.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := s.put(artifact, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(s, currentPaths, entryPath, &retention); err != nil {
				return err
			}
			if artifact.Scannable {
				s.coverage.FilesScanned++
				if artifact.SourceEncoding != "" {
					s.coverage.FilesTranscodedUTF16++
				}
			} else if artifact.ContentClass == ContentClassOversize {
				s.coverage.FilesSkippedOversize++
			} else {
				s.coverage.FilesExcludedBinary++
			}
		default:
			if err := drainEntry(entryReader); err != nil {
				return err
			}
			if err := s.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := s.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeOther,
				ContentClass: "",
				Scannable:    false,
			}, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(s, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		}
	}
	if _, err := io.Copy(io.Discard, limitedReader); err != nil {
		return classifyDrainError(descriptor, err)
	}
	if _, err := io.Copy(io.Discard, newContextReader(ctx, blob)); err != nil {
		return fmt.Errorf("drain layer blob: %w", err)
	}
	if verifier, ok := blob.(interface{ Verify() error }); ok {
		if err := verifier.Verify(); err != nil {
			return fmt.Errorf("verify layer blob: %w", err)
		}
	}

	for _, directory := range opaqueDirectories {
		s.deleteLowerPrefix(directory, descriptor.Digest, journal)
	}
	for _, target := range whiteouts {
		s.deleteLowerPath(target, descriptor.Digest, journal)
	}
	s.coverage.ExpandedBytes = expandedBytesAfterLayer(journal.coverage.ExpandedBytes, limitedReader.readBytes, logicalBudget.bytes)
	nested.flush(s)
	s.entries += entryCount
	s.endLayer()
	committed = true
	return nil
}

// flush adds the expander's observations to the state's coverage and skip
// records. It is idempotent so both the commit and the failure path can call it.
func (e *nestedExpander) flush(state *State) {
	if e == nil || e.flushed {
		return
	}
	e.flushed = true
	state.coverage.NestedArchivesExpanded += e.archivesExpanded
	state.coverage.NestedEntriesScanned += e.entriesScanned
	state.coverage.NestedEntriesSeen += e.entriesSeen
	state.coverage.NestedBytesExpanded += e.bytesExpanded
	room := maxNestedSkipRecords - len(state.nestedSkips)
	if room < 0 {
		room = 0
	}
	if len(e.skips) > room {
		state.coverage.NestedSkipsDropped += len(e.skips) - room
		e.skips = e.skips[:room]
	}
	state.coverage.NestedSkipsDropped += e.skipsDropped
	state.nestedSkips = append(append([]NestedSkip(nil), state.nestedSkips...), e.skips...)
}

// classifyDrainError names bytes left after the archive's end-of-archive
// marker. Once tar.Reader has returned io.EOF the decompressor is asked to
// read on; a gzip reader then expects another member header and a zstd reader
// another frame magic, so a header or magic failure there (or a fragment too
// short to be either) means the blob carries data that is not part of the
// archive. Limit, cancellation and checksum failures keep their own meaning.
func classifyDrainError(descriptor manifest.Descriptor, err error) error {
	if limits.IsExceeded(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("drain layer: %w", err)
	}
	trailing := false
	switch manifest.LayerCompression(descriptor.MediaType) {
	case "gzip":
		trailing = errors.Is(err, gzip.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF)
	case "zstd":
		trailing = errors.Is(err, zstd.ErrMagicMismatch) || errors.Is(err, io.ErrUnexpectedEOF)
	}
	if trailing {
		return &TrailingDataError{Digest: descriptor.Digest, Cause: err}
	}
	return fmt.Errorf("drain layer: %w", err)
}

type logicalLayerBudget struct {
	subject       string
	maxBytes      int64
	previousBytes int64
	maxTotalBytes int64
	bytes         int64
}

func newLogicalLayerBudget(digest string, maxBytes, previousBytes, maxTotalBytes int64) *logicalLayerBudget {
	return &logicalLayerBudget{
		subject:       "layer " + strings.TrimSpace(digest),
		maxBytes:      maxBytes,
		previousBytes: previousBytes,
		maxTotalBytes: maxTotalBytes,
	}
}

func (b *logicalLayerBudget) add(size int64) error {
	if size < 0 {
		return fmt.Errorf("layer entry has negative logical size")
	}
	if b.bytes > math.MaxInt64-size {
		b.bytes = math.MaxInt64
		if b.maxBytes <= 0 && b.maxTotalBytes > 0 {
			return limits.NewExceeded(limits.Kind("image_layer_bytes"), b.maxTotalBytes, "image")
		}
		return limits.NewExceeded(limits.KindLayerBytes, effectiveLimit(b.maxBytes), b.subject)
	}
	b.bytes += size
	if b.maxBytes > 0 && b.bytes > b.maxBytes {
		return limits.NewExceeded(limits.KindLayerBytes, b.maxBytes, b.subject)
	}
	if b.previousBytes > math.MaxInt64-b.bytes {
		return limits.NewExceeded(limits.Kind("image_layer_bytes"), effectiveLimit(b.maxTotalBytes), "image")
	}
	if b.maxTotalBytes > 0 && b.previousBytes+b.bytes > b.maxTotalBytes {
		return limits.NewExceeded(limits.Kind("image_layer_bytes"), b.maxTotalBytes, "image")
	}
	return nil
}

func effectiveLimit(configured int64) int64 {
	if configured > 0 {
		return configured
	}
	return math.MaxInt64
}

func expandedBytesAfterLayer(previous, physical, logical int64) int64 {
	current := physical
	if logical > current {
		current = logical
	}
	if previous > math.MaxInt64-current {
		return math.MaxInt64
	}
	return previous + current
}

type retentionBudget struct {
	maxBytes  int64
	temporary int64
}

func (b *retentionBudget) ensure(state *State, additional int64) error {
	used, ok := checkedRetainedAdd(state.coverage.RetainedBytes, b.temporary)
	if !ok {
		return limits.NewExceeded(limits.Kind("retained_bytes"), b.maxBytes, "image")
	}
	total, ok := checkedRetainedAdd(used, additional)
	if !ok || (b.maxBytes > 0 && total > b.maxBytes) {
		return limits.NewExceeded(limits.Kind("retained_bytes"), b.maxBytes, "image")
	}
	return nil
}

func (b *retentionBudget) retainPersistent(state *State, additional int64) error {
	if err := b.ensure(state, additional); err != nil {
		return err
	}
	state.coverage.RetainedBytes += additional
	return nil
}

func (b *retentionBudget) retainTemporary(state *State, additional int64) error {
	if err := b.ensure(state, additional); err != nil {
		return err
	}
	b.temporary += additional
	return nil
}

func checkedRetainedAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func retainedFinalArtifactBaseBytes(artifactPath, linkname string) int64 {
	return retainedArtifactMetadataBytes + retainedMapEntryMetadataBytes + retainedPathIndexMetadataBytes + int64(len(artifactPath)) + int64(len(linkname))
}

func retainedFinalArtifactBytes(artifact Artifact) int64 {
	return retainedFinalArtifactBaseBytes(artifact.Path, artifact.Linkname) + int64(len(artifact.Content)) + nestedRetainedBytes(artifact.Nested)
}

func retainedDeletedArtifactBytes(artifact Artifact) int64 {
	return retainedArtifactMetadataBytes + int64(len(artifact.Path)) + int64(len(artifact.Linkname)) + int64(len(artifact.Content)) + nestedRetainedBytes(artifact.Nested)
}

func retainedMapStringBytes(value string) int64 {
	return retainedMapEntryMetadataBytes + retainedPathIndexMetadataBytes + int64(len(value))
}

func retainedSliceStringBytes(value string) int64 {
	return retainedSliceEntryMetadataBytes + int64(len(value))
}

func retainCurrentPath(state *State, currentPaths map[string]struct{}, value string, budget *retentionBudget) error {
	if _, ok := currentPaths[value]; ok {
		return nil
	}
	if err := budget.retainTemporary(state, retainedMapStringBytes(value)); err != nil {
		return err
	}
	currentPaths[value] = struct{}{}
	return nil
}

func (s *State) put(artifact Artifact, budget *retentionBudget) error {
	if _, ok := s.final[artifact.Path]; ok {
		s.deletePath(artifact.Path, artifact.LayerDigest)
	}
	if err := budget.retainPersistent(s, retainedFinalArtifactBytes(artifact)); err != nil {
		return err
	}
	s.setFinal(artifact)
	s.removeDirectory(artifact.Path)
	return nil
}

func (s *State) addDirectory(target string, budget *retentionBudget) error {
	if _, ok := s.dirs[target]; ok {
		return nil
	}
	if err := budget.retainPersistent(s, retainedMapStringBytes(target)); err != nil {
		return err
	}
	s.journal.record(undoRecord{kind: undoDirAdd, path: target})
	if s.journal != nil {
		s.journal.createdDirs[target] = struct{}{}
	}
	s.dirs[target] = struct{}{}
	addPathIndexEntry(s.directoryChildren, target)
	return nil
}

func (s *State) removeDirectory(target string) {
	if _, ok := s.dirs[target]; !ok {
		return
	}
	if len(s.directoryChildren[target]) > 0 || len(s.artifactChildren[target]) > 0 {
		return
	}
	s.journal.record(undoRecord{kind: undoDirRemove, path: target})
	if s.journal != nil {
		delete(s.journal.createdDirs, target)
	}
	delete(s.dirs, target)
	removePathIndexEntry(s.directoryChildren, target)
	s.coverage.RetainedBytes -= retainedMapStringBytes(target)
}

func (s *State) preparePath(target string, directory bool, deletedBy string, budget *retentionBudget) error {
	for ancestor := path.Dir(target); ancestor != "." && ancestor != ""; ancestor = path.Dir(ancestor) {
		if _, ok := s.dirs[ancestor]; ok {
			// Directories are prefix-closed: every ancestor of a known directory
			// is itself a known directory and never an artifact (this loop clears
			// files on the way up and file-over-directory transitions purge the
			// subtree). Stopping here keeps the cost per entry proportional to
			// the new directories it introduces; walking the whole chain costs
			// O(depth) hashes per entry, which a hostile layer of 4 KiB-deep
			// paths turns into minutes of CPU within the default entry limits.
			break
		}
		if _, ok := s.final[ancestor]; ok {
			s.deletePath(ancestor, deletedBy)
		}
		if err := s.addDirectory(ancestor, budget); err != nil {
			return err
		}
	}
	if directory {
		if _, ok := s.final[target]; ok {
			s.deletePath(target, deletedBy)
		}
		return nil
	}
	if _, ok := s.dirs[target]; ok {
		s.deletePrefix(target, deletedBy)
		s.deleteDirectoryPrefix(target)
	}
	return nil
}

func (s *State) deletePath(targetPath, deletedBy string) {
	current, ok := s.final[targetPath]
	if !ok {
		return
	}

	s.unsetFinal(targetPath, current)
	s.coverage.RetainedBytes -= retainedFinalArtifactBytes(current)
	current.DeletedByLayerDigest = deletedBy
	if current.Type == ArtifactTypeRegularFile || current.Type == ArtifactTypeHardlink {
		s.deleted = append(s.deleted, current)
		s.coverage.RetainedBytes += retainedDeletedArtifactBytes(current)
	}
}

func (s *State) deletePrefix(directoryPath, deletedBy string) {
	directoryPath = strings.Trim(directoryPath, "/")
	for _, target := range s.artifactPathsBelow(directoryPath) {
		s.deletePath(target, deletedBy)
	}
}

func addPathIndexEntry(index map[string]map[string]struct{}, value string) {
	parent := parentPath(value)
	children := index[parent]
	if children == nil {
		children = make(map[string]struct{})
		index[parent] = children
	}
	children[value] = struct{}{}
}

func removePathIndexEntry(index map[string]map[string]struct{}, value string) {
	parent := parentPath(value)
	children := index[parent]
	delete(children, value)
	if len(children) == 0 {
		delete(index, parent)
	}
}

func parentPath(value string) string {
	parent := path.Dir(value)
	if parent == "." || parent == "/" {
		return ""
	}
	return parent
}

func (s *State) artifactPathsBelow(directory string) []string {
	directory = indexDirectoryPath(directory)
	result := make([]string, 0)
	stack := []string{directory}
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		for artifactPath := range s.artifactChildren[current] {
			result = append(result, artifactPath)
		}
		for child := range s.directoryChildren[current] {
			stack = append(stack, child)
		}
	}
	return result
}

func (s *State) directoryPathsAtOrBelow(directory string) []string {
	directory = indexDirectoryPath(directory)
	result := make([]string, 0)
	type visit struct {
		path     string
		children bool
	}
	stack := []visit{{path: directory}}
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.children {
			if _, ok := s.dirs[current.path]; ok {
				result = append(result, current.path)
			}
			continue
		}
		stack = append(stack, visit{path: current.path, children: true})
		for child := range s.directoryChildren[current.path] {
			stack = append(stack, visit{path: child})
		}
	}
	return result
}

func indexDirectoryPath(value string) string {
	value = strings.Trim(value, "/")
	if value == "." {
		return ""
	}
	return value
}

func (s *State) deleteDirectoryPrefix(target string) {
	for _, candidate := range s.directoryPathsAtOrBelow(target) {
		s.removeDirectory(candidate)
	}
}

func buildRegularArtifact(entryPath, layerDigest string, reader io.Reader, size int64, options ReplayOptions, nested *nestedExpander) (Artifact, error) {
	maxFileBytes := options.MaxFileBytes
	limited := io.LimitReader(reader, limits.OverflowProbeLimit(maxFileBytes))
	content, err := io.ReadAll(limited)
	if err != nil {
		return Artifact{}, fmt.Errorf("read layer file %q: %w", boundedPathForError(entryPath), err)
	}

	var expanded []Artifact
	if nested.isCandidate(content) {
		archive := content
		if int64(len(content)) > maxFileBytes {
			// The file is too large to scan as a whole but may still be an
			// archive worth opening: buffer it up to the nested limit. The
			// declared size is checked first so a huge archive is not read at
			// all, and the read itself is capped in case the size lies.
			archive = nil
			if size <= options.MaxNestedArchiveBytes {
				more, err := io.ReadAll(io.LimitReader(reader, limits.OverflowProbeLimit(options.MaxNestedArchiveBytes)-int64(len(content))))
				if err != nil {
					return Artifact{}, fmt.Errorf("read layer file %q: %w", boundedPathForError(entryPath), err)
				}
				archive = append(content, more...)
				if int64(len(archive)) > options.MaxNestedArchiveBytes {
					nested.skip(entryPath, NestedSkipOversize, int64(len(archive)), options.MaxNestedArchiveBytes)
					archive = nil
				}
			} else {
				nested.skip(entryPath, NestedSkipOversize, size, options.MaxNestedArchiveBytes)
			}
			if archive != nil {
				content = archive[:len(content)]
			}
		}
		if archive != nil {
			expanded = nested.expand(entryPath, archive)
		}
	}

	if _, err := io.Copy(io.Discard, reader); err != nil {
		return Artifact{}, fmt.Errorf("discard remaining file bytes for %q: %w", boundedPathForError(entryPath), err)
	}

	artifact := classifyRegularContent(entryPath, layerDigest, content, size, maxFileBytes)
	artifact.Nested = expanded
	return artifact, nil
}

// classifyRegularContent builds the artifact for a regular file whose first
// maxFileBytes+1 bytes are content: oversize files keep no content, UTF-16
// text is transcoded, and only text is scannable.
func classifyRegularContent(entryPath, layerDigest string, content []byte, size, maxFileBytes int64) Artifact {
	var contentClass ContentClass
	var encoding TextEncoding
	scannable := int64(len(content)) <= maxFileBytes
	if !scannable {
		contentClass = ContentClassOversize
		content = nil
	} else {
		content, encoding, scannable = transcodeTextContent(content, maxFileBytes)
		if !scannable {
			// The UTF-8 form of a UTF-16 file is subject to the per-file limit
			// exactly as a file stored in UTF-8 is.
			contentClass = ContentClassOversize
			content = nil
			encoding = ""
		} else {
			contentClass = classifyContent(entryPath, content)
			scannable = contentClass == ContentClassText
			if !scannable {
				content = nil
				encoding = ""
			}
		}
	}

	return Artifact{
		Path:           entryPath,
		LayerDigest:    layerDigest,
		Type:           ArtifactTypeRegularFile,
		Content:        content,
		Size:           size,
		ContentClass:   contentClass,
		Scannable:      scannable,
		SourceEncoding: encoding,
	}
}

// transcodeTextContent returns content in UTF-8 for classification. UTF-16
// text (with a byte-order mark or in the alternating-NUL shape) is decoded so
// that it is scanned instead of being excluded as binary for its NUL bytes;
// every other content is returned as stored. The boolean is false only when a
// transcoded file's UTF-8 form exceeds maxBytes.
func transcodeTextContent(content []byte, maxBytes int64) ([]byte, TextEncoding, bool) {
	encoding, bomLength := detectUTF16(content)
	if encoding == "" {
		return content, "", true
	}
	decoded, ok := transcodeUTF16(content, encoding, bomLength, maxBytes)
	if !ok {
		return nil, encoding, false
	}
	return decoded, encoding, true
}

func boundedPathForError(value string) string {
	const maxRunes = 256
	runes := []rune(value)
	if len(runes) > maxRunes {
		runes = append(runes[:maxRunes], '…')
	}
	return string(runes)
}

func classifyContent(entryPath string, content []byte) ContentClass {
	if len(content) == 0 {
		return ContentClassText
	}

	sharedObject := hasSharedObjectSignature(entryPath)
	if hasELFMagic(content) {
		if sharedObject {
			return ContentClassBinarySharedObject
		}
		return ContentClassBinaryELF
	}
	if sharedObject && (hasNULByte(content) || printableRatio(content) < 0.85) {
		return ContentClassBinarySharedObject
	}
	if hasNULByte(content) {
		return ContentClassBinaryNUL
	}
	if printableRatio(content) < 0.85 {
		return ContentClassBinaryLowPrintable
	}
	return ContentClassText
}

func hasELFMagic(content []byte) bool {
	return len(content) >= 4 &&
		content[0] == 0x7f &&
		content[1] == 'E' &&
		content[2] == 'L' &&
		content[3] == 'F'
}

func hasSharedObjectSignature(entryPath string) bool {
	base := path.Base(entryPath)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func hasNULByte(content []byte) bool {
	for _, b := range content {
		if b == 0x00 {
			return true
		}
	}
	return false
}

func printableRatio(content []byte) float64 {
	if len(content) == 0 {
		return 1
	}

	total := 0
	printable := 0
	if utf8.Valid(content) {
		for _, r := range string(content) {
			total++
			if isPrintableRune(r) {
				printable++
			}
		}
	} else {
		for _, b := range content {
			total++
			if isPrintableByte(b) {
				printable++
			}
		}
	}

	if total == 0 {
		return 1
	}
	return float64(printable) / float64(total)
}

func isPrintableRune(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return true
	}
	return unicode.IsPrint(r)
}

func isPrintableByte(value byte) bool {
	switch value {
	case '\n', '\r', '\t':
		return true
	}
	return value >= 0x20 && value <= 0x7e
}

func decompressLayer(mediaType string, reader io.Reader) (io.Reader, func(), error) {
	switch manifest.LayerCompression(mediaType) {
	case "":
		return reader, func() {}, nil
	case "gzip":
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("open gzip layer: %w", err)
		}
		return gzipReader, func() {
			// Stream errors surface through Read; Close only releases decoder state.
			_ = gzipReader.Close()
		}, nil
	case "zstd":
		decoder, err := zstd.NewReader(
			reader,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(zstdDecoderWindowLimit),
			zstd.WithDecoderMaxMemory(zstdDecoderWindowLimit),
			zstd.WithDecodeBuffersBelow(0),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("open zstd layer: %w", err)
		}
		return decoder, func() {
			decoder.Close()
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported layer compression for media type: %s", mediaType)
	}
}

type layerLimitReader struct {
	reader        io.Reader
	subject       string
	maxBytes      int64
	previousBytes int64
	maxTotalBytes int64
	readBytes     int64
}

func newLayerLimitReader(reader io.Reader, digest string, maxBytes, previousBytes, maxTotalBytes int64) *layerLimitReader {
	return &layerLimitReader{
		reader:        reader,
		subject:       "layer " + strings.TrimSpace(digest),
		maxBytes:      maxBytes,
		previousBytes: previousBytes,
		maxTotalBytes: maxTotalBytes,
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func newContextReader(ctx context.Context, reader io.Reader) io.Reader {
	return &contextReader{ctx: ctx, reader: reader}
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := contextError(r.ctx); err != nil {
		return 0, err
	}
	count, err := r.reader.Read(buffer)
	if err == nil {
		if contextErr := contextError(r.ctx); contextErr != nil {
			return count, contextErr
		}
	}
	return count, err
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func (r *layerLimitReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}

	maxRead := int64(len(buffer))
	if r.maxBytes > 0 {
		remaining := r.maxBytes - r.readBytes
		if remaining < maxRead {
			maxRead = limits.OverflowProbeLimit(remaining)
		}
	}
	if r.maxTotalBytes > 0 {
		remaining := r.maxTotalBytes - r.previousBytes
		if r.readBytes > remaining {
			remaining = -1
		} else {
			remaining -= r.readBytes
		}
		if remaining < maxRead {
			maxRead = limits.OverflowProbeLimit(remaining)
		}
	}
	if maxRead <= 0 {
		maxRead = 1
	}

	count, err := r.reader.Read(buffer[:int(maxRead)])
	r.readBytes += int64(count)
	if r.maxBytes > 0 && r.readBytes > r.maxBytes {
		return count, limits.NewExceeded(limits.KindLayerBytes, r.maxBytes, r.subject)
	}
	if r.maxTotalBytes > 0 && (r.previousBytes > r.maxTotalBytes || r.readBytes > r.maxTotalBytes-r.previousBytes) {
		return count, limits.NewExceeded(limits.Kind("image_layer_bytes"), r.maxTotalBytes, "image")
	}
	return count, err
}

func normalizePath(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("path is required")
	}
	if len(value) > maxArchivePathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", maxArchivePathBytes)
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if strings.Contains(value, `\`) {
		return "", fmt.Errorf("path must use forward slashes")
	}
	if path.IsAbs(value) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return "", fmt.Errorf("parent traversal is not allowed")
		}
	}

	cleaned := path.Clean(value)
	if cleaned == "" || cleaned == "." {
		return "", errRootEntry
	}

	return cleaned, nil
}

// errRootEntry marks an archive entry that names the layer root (`.` or `./`).
var errRootEntry = errors.New("entry names the archive root")

func validateLinkname(value string) error {
	if len(value) > maxArchivePathBytes {
		return fmt.Errorf("link target exceeds %d bytes", maxArchivePathBytes)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("link target contains a NUL byte")
	}
	return nil
}

func isWhiteout(entryPath string) bool {
	base := path.Base(entryPath)
	return strings.HasPrefix(base, ".wh.") && base != ".wh..wh..opq"
}

func isOpaqueWhiteout(entryPath string) bool {
	return path.Base(entryPath) == ".wh..wh..opq"
}

func whiteoutTarget(entryPath string) (string, error) {
	base := strings.TrimPrefix(path.Base(entryPath), ".wh.")
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("whiteout target is required")
	}
	target := path.Join(path.Dir(entryPath), base)
	if target == "." {
		return base, nil
	}
	return strings.TrimPrefix(path.Clean(target), "/"), nil
}

func drainEntry(reader io.Reader) error {
	_, err := io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("drain tar entry: %w", err)
	}
	return nil
}

func sortArtifacts(items []Artifact) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path == items[j].Path {
			if items[i].LayerDigest == items[j].LayerDigest {
				return items[i].DeletedByLayerDigest < items[j].DeletedByLayerDigest
			}
			return items[i].LayerDigest < items[j].LayerDigest
		}
		return items[i].Path < items[j].Path
	})
}
