package layers

import (
	"archive/tar"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// ErrCacheUnusable reports that a layer replayed from the sweep cache cannot
// serve this manifest: a later layer hardlinks to one of its text files, and
// detectors judge content by path, so the content itself is needed. The
// caller replays the manifest without cache lookups (recording still runs).
var ErrCacheUnusable = errors.New("layer cache cannot serve this manifest: content of a cached layer is needed")

// LayerCache remembers, per layer digest, the entry list of a layer whose
// files detection found nothing in, so a sweep (`--all-tags`) does not fetch,
// decompress and parse the same base layers for every tag. It is scoped to
// one sweep, bounded in bytes and evicts least-recently-used layers.
//
// A cached layer holds metadata only: entry names, types, sizes, content
// classes and the physical stream positions that make limit enforcement
// reproducible. It never holds file content, so no secret bytes live in it;
// a layer with any finding, with nested archives or with a hardlink whose
// target is not a file of the same layer (another layer's file, a directory
// or nothing at all) is never cached. Replaying from the cache is
// byte-identical to replaying from the registry.
type LayerCache struct {
	mu        sync.Mutex
	maxBytes  int64
	usedBytes int64
	order     *list.List
	entries   map[string]*list.Element
	stats     LayerCacheStats
}

// LayerCacheStats counts the cache's activity over its lifetime.
type LayerCacheStats struct {
	Hits      int
	Misses    int
	Stores    int
	Rejected  int
	Evictions int
	Layers    int
	UsedBytes int64
}

// NewLayerCache returns a cache bounded by maxBytes, or nil (no caching) when
// maxBytes is not positive.
func NewLayerCache(maxBytes int64) *LayerCache {
	if maxBytes <= 0 {
		return nil
	}
	return &LayerCache{maxBytes: maxBytes, order: list.New(), entries: make(map[string]*list.Element)}
}

// Stats returns a snapshot of the counters; a nil cache reports zeros.
func (c *LayerCache) Stats() LayerCacheStats {
	if c == nil {
		return LayerCacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := c.stats
	stats.Layers = len(c.entries)
	stats.UsedBytes = c.usedBytes
	return stats
}

func cacheKey(descriptor manifest.Descriptor) string {
	return descriptor.Digest + "|" + manifest.LayerCompression(descriptor.MediaType)
}

// lookup returns the record for the descriptor and marks it recently used.
func (c *LayerCache) lookup(descriptor manifest.Descriptor) *LayerRecord {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[cacheKey(descriptor)]
	if !ok {
		c.stats.Misses++
		return nil
	}
	c.stats.Hits++
	c.order.MoveToFront(element)
	return element.Value.(*LayerRecord)
}

// Store keeps a record, evicting least-recently-used layers to make room. A
// record larger than the whole cache is rejected. It returns whether the
// record is now cached.
func (c *LayerCache) Store(record *LayerRecord) bool {
	if c == nil || record == nil || !record.cacheable {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if record.size > c.maxBytes {
		c.stats.Rejected++
		return false
	}
	if element, ok := c.entries[record.key]; ok {
		c.order.MoveToFront(element)
		return true
	}
	for c.usedBytes+record.size > c.maxBytes {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		evicted := c.order.Remove(oldest).(*LayerRecord)
		delete(c.entries, evicted.key)
		c.usedBytes -= evicted.size
		c.stats.Evictions++
	}
	c.entries[record.key] = c.order.PushFront(record)
	c.usedBytes += record.size
	c.stats.Stores++
	return true
}

// LayerRecord is one layer's entry list as the tar replay observed it, with
// the stream positions needed to enforce the byte limits identically when the
// layer is replayed from the cache instead of the registry.
type LayerRecord struct {
	Digest      string
	key         string
	entries     []cachedEntry
	physicalEnd int64
	size        int64
	cacheable   bool
}

// cachedEntry mirrors one tar header plus, for regular files, the artifact
// metadata that classification produced. Content is never kept.
type cachedEntry struct {
	name           string
	linkname       string
	typeflag       byte
	size           int64
	physicalHeader int64
	physicalBody   int64
	contentLength  int64
	contentClass   ContentClass
	scannable      bool
	sourceEncoding TextEncoding
}

const (
	cachedLayerBaseBytes = 128
	// cachedEntryBaseBytes approximates the heap cost of one cachedEntry:
	// four string headers (name, linkname, content class, encoding), four
	// int64s and the small fields with padding, plus slack for slice growth
	// by doubling. It deliberately errs high so the budget is not exceeded.
	cachedEntryBaseBytes  = 160
	cachedEntryStringCost = 1
)

func newLayerRecord(descriptor manifest.Descriptor) *LayerRecord {
	return &LayerRecord{
		Digest:    descriptor.Digest,
		key:       cacheKey(descriptor),
		cacheable: true,
		size:      cachedLayerBaseBytes + int64(len(descriptor.Digest)),
	}
}

func (r *LayerRecord) addEntry(entry cachedEntry) {
	r.entries = append(r.entries, entry)
	r.size += cachedEntryBaseBytes + cachedEntryStringCost*int64(len(entry.name)+len(entry.linkname))
}

// markUncacheable excludes the layer from the cache: its replay depends on
// content (hardlinks into other layers) or on budgets that vary with the
// layer stack (nested archive expansion).
func (r *LayerRecord) markUncacheable() {
	if r != nil {
		r.cacheable = false
	}
}

// layerEntry is one archive entry as the replay state machine consumes it,
// from the tar stream or from a cache record.
type layerEntry struct {
	name     string
	linkname string
	typeflag byte
	size     int64
	reader   io.Reader
	cached   *cachedEntry
}

// entrySource feeds applyEntries. The tar source parses the decompressed
// stream and records what it sees; the cached source replays a record and
// advances the same byte accounting to the recorded positions.
type entrySource interface {
	next() (layerEntry, error)
	drain(entry layerEntry) error
	regular(entry layerEntry, entryPath string, nested *nestedExpander) (Artifact, error)
	finish() error
	physical() int64
	fromCache() bool
	record() *LayerRecord
}

// cachedEntrySource replays a LayerRecord without a stream.
type cachedEntrySource struct {
	descriptor manifest.Descriptor
	layer      *LayerRecord
	limited    *layerLimitReader
	options    ReplayOptions
	index      int
}

func (c *cachedEntrySource) next() (layerEntry, error) {
	if c.index >= len(c.layer.entries) {
		return layerEntry{}, io.EOF
	}
	entry := &c.layer.entries[c.index]
	c.index++
	if err := c.limited.advance(entry.physicalHeader); err != nil {
		return layerEntry{}, err
	}
	return layerEntry{name: entry.name, linkname: entry.linkname, typeflag: entry.typeflag, size: entry.size, cached: entry}, nil
}

func (c *cachedEntrySource) drain(entry layerEntry) error {
	if err := c.limited.advance(entry.cached.physicalBody); err != nil {
		return fmt.Errorf("drain tar entry: %w", err)
	}
	return nil
}

func (c *cachedEntrySource) regular(entry layerEntry, entryPath string, _ *nestedExpander) (Artifact, error) {
	cached := entry.cached
	if err := c.limited.advance(cached.physicalBody); err != nil {
		// The stream would have failed either while buffering the first
		// MaxFileBytes+1 bytes or while discarding the rest; name the phase
		// the real replay would have named.
		readLimit := limits.OverflowProbeLimit(c.options.MaxFileBytes)
		if entry.size < readLimit {
			readLimit = entry.size
		}
		if c.limited.readBytes-cached.physicalHeader <= readLimit {
			return Artifact{}, fmt.Errorf("read layer file %q: %w", boundedPathForError(entryPath), err)
		}
		return Artifact{}, fmt.Errorf("discard remaining file bytes for %q: %w", boundedPathForError(entryPath), err)
	}
	return Artifact{
		Path:           entryPath,
		LayerDigest:    c.descriptor.Digest,
		Type:           ArtifactTypeRegularFile,
		Size:           entry.size,
		ContentClass:   cached.contentClass,
		Scannable:      cached.scannable,
		SourceEncoding: cached.sourceEncoding,
		ContentLength:  cached.contentLength,
		KnownClean:     cached.scannable,
	}, nil
}

func (c *cachedEntrySource) finish() error {
	if err := c.limited.advance(c.layer.physicalEnd); err != nil {
		return classifyDrainError(c.descriptor, err)
	}
	return nil
}

func (c *cachedEntrySource) physical() int64      { return c.limited.readBytes }
func (c *cachedEntrySource) fromCache() bool      { return true }
func (c *cachedEntrySource) record() *LayerRecord { return nil }

// tarEntrySource parses the decompressed layer stream and, when a cache is
// configured, records every entry with the stream positions at which its
// header and content ended.
type tarEntrySource struct {
	ctx        context.Context
	descriptor manifest.Descriptor
	blob       io.Reader
	limited    *layerLimitReader
	tarReader  *tar.Reader
	options    ReplayOptions
	layer      *LayerRecord
	current    *cachedEntry
}

func (t *tarEntrySource) next() (layerEntry, error) {
	header, err := t.tarReader.Next()
	if err != nil {
		return layerEntry{}, err
	}
	entry := layerEntry{
		name:     header.Name,
		linkname: header.Linkname,
		typeflag: header.Typeflag,
		size:     header.Size,
		// Sparse holes are synthesised by archive/tar without touching the
		// compressed stream, so the per-entry reader must observe ctx itself.
		reader: newContextReader(t.ctx, t.tarReader),
	}
	t.current = nil
	if t.layer != nil {
		t.layer.addEntry(cachedEntry{name: header.Name, linkname: header.Linkname, typeflag: header.Typeflag, size: header.Size, physicalHeader: t.limited.readBytes})
		t.current = &t.layer.entries[len(t.layer.entries)-1]
	}
	return entry, nil
}

func (t *tarEntrySource) drain(entry layerEntry) error {
	err := drainEntry(entry.reader)
	if t.current != nil {
		t.current.physicalBody = t.limited.readBytes
	}
	return err
}

func (t *tarEntrySource) regular(entry layerEntry, entryPath string, nested *nestedExpander) (Artifact, error) {
	artifact, err := buildRegularArtifact(entryPath, t.descriptor.Digest, entry.reader, entry.size, t.options, nested)
	if t.current != nil {
		t.current.physicalBody = t.limited.readBytes
		t.current.contentLength = artifact.ContentLength
		t.current.contentClass = artifact.ContentClass
		t.current.scannable = artifact.Scannable
		t.current.sourceEncoding = artifact.SourceEncoding
	}
	return artifact, err
}

func (t *tarEntrySource) finish() error {
	if _, err := io.Copy(io.Discard, t.limited); err != nil {
		return classifyDrainError(t.descriptor, err)
	}
	if t.layer != nil {
		t.layer.physicalEnd = t.limited.readBytes
	}
	if _, err := io.Copy(io.Discard, newContextReader(t.ctx, t.blob)); err != nil {
		return fmt.Errorf("drain layer blob: %w", err)
	}
	if verifier, ok := t.blob.(interface{ Verify() error }); ok {
		if err := verifier.Verify(); err != nil {
			return fmt.Errorf("verify layer blob: %w", err)
		}
	}
	return nil
}

func (t *tarEntrySource) physical() int64      { return t.limited.readBytes }
func (t *tarEntrySource) fromCache() bool      { return false }
func (t *tarEntrySource) record() *LayerRecord { return t.layer }

// advance moves the byte accounting to a recorded stream position, failing
// exactly where Read would have: the counter stops one byte past the
// tighter of the layer and image limits and the corresponding error is
// returned (the layer limit wins a tie, as in Read).
func (r *layerLimitReader) advance(to int64) error {
	if to <= r.readBytes {
		return nil
	}
	allowed := int64(math.MaxInt64)
	layerBound := false
	if r.maxBytes > 0 {
		allowed, layerBound = r.maxBytes, true
	}
	if r.maxTotalBytes > 0 {
		remaining := r.maxTotalBytes - r.previousBytes
		if remaining < 0 {
			remaining = -1
		}
		if remaining < allowed {
			allowed, layerBound = remaining, false
		}
	}
	if to > allowed {
		r.readBytes = limits.OverflowProbeLimit(allowed)
		if layerBound {
			return limits.NewExceeded(limits.KindLayerBytes, r.maxBytes, r.subject)
		}
		return limits.NewExceeded(limits.Kind("image_layer_bytes"), r.maxTotalBytes, "image")
	}
	r.readBytes = to
	return nil
}
