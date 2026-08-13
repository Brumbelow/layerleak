package layers

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
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
	minimumZstdDecoderLimit         = 1 << 20
	defaultZstdDecoderLimit         = 64 << 20
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
}

type ReplayResult struct {
	FinalFiles       []Artifact
	DeletedArtifacts []Artifact
	Coverage         Coverage
}

type ReplayOptions struct {
	MaxFileBytes     int64
	MaxLayerBytes    int64
	MaxLayerEntries  int
	MaxTotalBytes    int64
	MaxTotalEntries  int
	MaxRetainedBytes int64
}

type Coverage struct {
	LayersSeen           int
	LayersCompleted      int
	FilesSeen            int
	FilesScanned         int
	FilesSkippedOversize int
	FilesExcludedBinary  int
	EntriesSkippedUnsafe int
	ExpandedBytes        int64
	RetainedBytes        int64
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
	for _, descriptor := range descriptors {
		if err := contextError(ctx); err != nil {
			return state.Result(), err
		}
		state.coverage.LayersSeen++
		if manifest.IsForeignLayerMediaType(descriptor.MediaType) {
			return state.Result(), fmt.Errorf("foreign layer media type is not supported: %s", descriptor.MediaType)
		}
		if !manifest.IsLayerMediaType(descriptor.MediaType) {
			return state.Result(), fmt.Errorf("unsupported layer media type: %s", descriptor.MediaType)
		}

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
	reader, cleanup, err := decompressLayer(descriptor.MediaType, blob, options.MaxLayerBytes)
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
	base := s
	working := &State{
		final:             cloneArtifactMap(s.final),
		deleted:           append([]Artifact(nil), s.deleted...),
		dirs:              cloneDirectoryMap(s.dirs),
		directoryChildren: clonePathIndex(s.directoryChildren),
		artifactChildren:  clonePathIndex(s.artifactChildren),
		entries:           s.entries,
		coverage:          s.coverage,
	}
	retention := retentionBudget{maxBytes: options.MaxRetainedBytes}
	committed := false
	defer func() {
		if committed {
			return
		}
		observed := working.coverage
		observed.ExpandedBytes = expandedBytesAfterLayer(s.coverage.ExpandedBytes, limitedReader.readBytes, logicalBudget.bytes)
		observed.RetainedBytes = s.coverage.RetainedBytes
		s.coverage = observed
	}()
	currentPaths := make(map[string]struct{})
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
			working.coverage.EntriesSkippedUnsafe++
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			continue
		}
		if err := validateLinkname(header.Linkname); err != nil {
			working.coverage.EntriesSkippedUnsafe++
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			continue
		}

		if isOpaqueWhiteout(entryPath) {
			directory := path.Dir(entryPath)
			if err := retention.retainTemporary(working, retainedSliceStringBytes(directory)); err != nil {
				return err
			}
			opaqueDirectories = append(opaqueDirectories, directory)
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			continue
		}
		if isWhiteout(entryPath) {
			target, targetErr := whiteoutTarget(entryPath)
			if targetErr != nil {
				working.coverage.EntriesSkippedUnsafe++
			} else {
				if err := retention.retainTemporary(working, retainedSliceStringBytes(target)); err != nil {
					return err
				}
				whiteouts = append(whiteouts, target)
			}
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			if err := working.preparePath(entryPath, true, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := working.addDirectory(entryPath, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(working, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			if err := working.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := working.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeSymlink,
				Linkname:     header.Linkname,
				ContentClass: "",
				Scannable:    false,
			}, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(working, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			linkTarget, err := normalizePath(header.Linkname)
			if err != nil {
				working.coverage.EntriesSkippedUnsafe++
				continue
			}
			target, ok := working.final[linkTarget]
			if !ok {
				working.coverage.EntriesSkippedUnsafe++
				continue
			}
			working.coverage.FilesSeen++
			copyContent := target.Content
			if err := working.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := working.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeHardlink,
				Linkname:     linkTarget,
				Content:      copyContent,
				Size:         target.Size,
				ContentClass: target.ContentClass,
				Scannable:    target.Scannable,
			}, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(working, currentPaths, entryPath, &retention); err != nil {
				return err
			}
			if target.Scannable {
				working.coverage.FilesScanned++
			} else if target.ContentClass == ContentClassOversize {
				working.coverage.FilesSkippedOversize++
			} else {
				working.coverage.FilesExcludedBinary++
			}
		case tar.TypeReg, tar.TypeRegA:
			working.coverage.FilesSeen++
			if header.Size <= options.MaxFileBytes {
				prospective := retainedFinalArtifactBaseBytes(entryPath, "") + header.Size
				if err := retention.ensure(working, prospective); err != nil {
					return err
				}
			}
			artifact, err := buildRegularArtifact(entryPath, descriptor.Digest, tarReader, header.Size, options.MaxFileBytes)
			if err != nil {
				return err
			}
			if err := working.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := working.put(artifact, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(working, currentPaths, entryPath, &retention); err != nil {
				return err
			}
			if artifact.Scannable {
				working.coverage.FilesScanned++
			} else if artifact.ContentClass == ContentClassOversize {
				working.coverage.FilesSkippedOversize++
			} else {
				working.coverage.FilesExcludedBinary++
			}
		default:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			if err := working.preparePath(entryPath, false, descriptor.Digest, &retention); err != nil {
				return err
			}
			if err := working.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeOther,
				ContentClass: "",
				Scannable:    false,
			}, &retention); err != nil {
				return err
			}
			if err := retainCurrentPath(working, currentPaths, entryPath, &retention); err != nil {
				return err
			}
		}
	}
	if _, err := io.Copy(io.Discard, limitedReader); err != nil {
		return fmt.Errorf("drain layer: %w", err)
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
		working.deleteLowerPrefix(base, directory, descriptor.Digest, currentPaths)
	}
	for _, target := range whiteouts {
		working.deleteLowerPath(base, target, descriptor.Digest, currentPaths)
	}
	working.coverage.ExpandedBytes = expandedBytesAfterLayer(s.coverage.ExpandedBytes, limitedReader.readBytes, logicalBudget.bytes)
	s.final = working.final
	s.deleted = working.deleted
	s.dirs = working.dirs
	s.directoryChildren = working.directoryChildren
	s.artifactChildren = working.artifactChildren
	s.entries = s.entries + entryCount
	s.coverage = working.coverage
	committed = true
	return nil
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
	return retainedFinalArtifactBaseBytes(artifact.Path, artifact.Linkname) + int64(len(artifact.Content))
}

func retainedDeletedArtifactBytes(artifact Artifact) int64 {
	return retainedArtifactMetadataBytes + int64(len(artifact.Path)) + int64(len(artifact.Linkname)) + int64(len(artifact.Content))
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
	s.final[artifact.Path] = artifact
	addPathIndexEntry(s.artifactChildren, artifact.Path)
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
	delete(s.dirs, target)
	removePathIndexEntry(s.directoryChildren, target)
	s.coverage.RetainedBytes -= retainedMapStringBytes(target)
}

func (s *State) preparePath(target string, directory bool, deletedBy string, budget *retentionBudget) error {
	for ancestor := path.Dir(target); ancestor != "." && ancestor != ""; ancestor = path.Dir(ancestor) {
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

	delete(s.final, targetPath)
	removePathIndexEntry(s.artifactChildren, targetPath)
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

func (s *State) deleteLowerPath(base *State, target, deletedBy string, currentPaths map[string]struct{}) {
	if _, sameLayer := currentPaths[target]; !sameLayer {
		if current, ok := base.final[target]; ok {
			s.deleteArtifactIfEqual(target, current, deletedBy)
		}
	}
	if _, ok := base.dirs[target]; ok {
		s.deleteLowerPrefix(base, target, deletedBy, currentPaths)
	}
}

func (s *State) deleteLowerPrefix(base *State, directory, deletedBy string, currentPaths map[string]struct{}) {
	directory = strings.Trim(directory, "/")
	for _, target := range base.artifactPathsBelow(directory) {
		if _, sameLayer := currentPaths[target]; sameLayer {
			continue
		}
		s.deleteArtifactIfEqual(target, base.final[target], deletedBy)
	}
	for _, target := range base.directoryPathsAtOrBelow(directory) {
		if _, sameLayer := currentPaths[target]; !sameLayer {
			s.removeDirectory(target)
		}
	}
}

func (s *State) deleteArtifactIfEqual(target string, lower Artifact, deletedBy string) {
	current, ok := s.final[target]
	if !ok || current.LayerDigest != lower.LayerDigest || current.Type != lower.Type {
		return
	}
	delete(s.final, target)
	removePathIndexEntry(s.artifactChildren, target)
	s.coverage.RetainedBytes -= retainedFinalArtifactBytes(current)
	lower.DeletedByLayerDigest = deletedBy
	if lower.Type == ArtifactTypeRegularFile || lower.Type == ArtifactTypeHardlink {
		s.deleted = append(s.deleted, lower)
		s.coverage.RetainedBytes += retainedDeletedArtifactBytes(lower)
	}
}

func cloneArtifactMap(source map[string]Artifact) map[string]Artifact {
	result := make(map[string]Artifact, len(source))
	for key, artifact := range source {
		// Artifact content is immutable after construction. Sharing its backing
		// bytes keeps transactional layer snapshots bounded by map metadata rather
		// than duplicating the retained image for every layer.
		result[key] = artifact
	}
	return result
}

func cloneDirectoryMap(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for key := range source {
		result[key] = struct{}{}
	}
	return result
}

func clonePathIndex(source map[string]map[string]struct{}) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{}, len(source))
	for parent, children := range source {
		cloned := make(map[string]struct{}, len(children))
		for child := range children {
			cloned[child] = struct{}{}
		}
		result[parent] = cloned
	}
	return result
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

func buildRegularArtifact(entryPath, layerDigest string, reader io.Reader, size, maxFileBytes int64) (Artifact, error) {
	limited := io.LimitReader(reader, limits.OverflowProbeLimit(maxFileBytes))
	content, err := io.ReadAll(limited)
	if err != nil {
		return Artifact{}, fmt.Errorf("read layer file %q: %w", boundedPathForError(entryPath), err)
	}

	contentClass := ContentClassText
	scannable := int64(len(content)) <= maxFileBytes
	if !scannable {
		contentClass = ContentClassOversize
		content = nil
	} else {
		contentClass = classifyContent(entryPath, content)
		scannable = contentClass == ContentClassText
		if !scannable {
			content = nil
		}
	}

	if _, err := io.Copy(io.Discard, reader); err != nil {
		return Artifact{}, fmt.Errorf("discard remaining file bytes for %q: %w", boundedPathForError(entryPath), err)
	}

	return Artifact{
		Path:         entryPath,
		LayerDigest:  layerDigest,
		Type:         ArtifactTypeRegularFile,
		Content:      content,
		Size:         size,
		ContentClass: contentClass,
		Scannable:    scannable,
	}, nil
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

func decompressLayer(mediaType string, reader io.Reader, maxLayerBytes int64) (io.Reader, func(), error) {
	switch manifest.LayerCompression(mediaType) {
	case "":
		return reader, func() {}, nil
	case "gzip":
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("open gzip layer: %w", err)
		}
		return gzipReader, func() {
			gzipReader.Close()
		}, nil
	case "zstd":
		decoderLimit := zstdDecoderLimit(maxLayerBytes)
		decoder, err := zstd.NewReader(
			reader,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(decoderLimit),
			zstd.WithDecoderMaxMemory(decoderLimit),
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

func zstdDecoderLimit(maxLayerBytes int64) uint64 {
	if maxLayerBytes <= 0 {
		return defaultZstdDecoderLimit
	}
	if maxLayerBytes < minimumZstdDecoderLimit {
		return minimumZstdDecoderLimit
	}
	if maxLayerBytes > zstd.MaxWindowSize {
		return zstd.MaxWindowSize
	}
	return uint64(maxLayerBytes)
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
		return "", fmt.Errorf("path is required")
	}

	return cleaned, nil
}

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
