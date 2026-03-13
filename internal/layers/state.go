package layers

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"github.com/klauspost/compress/zstd"
)

type ArtifactType string

const (
	ArtifactTypeRegularFile ArtifactType = "regular"
	ArtifactTypeHardlink    ArtifactType = "hardlink"
	ArtifactTypeSymlink     ArtifactType = "symlink"
)

type ContentClass string

const (
	ContentClassText               ContentClass = "text"
	ContentClassOversize           ContentClass = "oversize"
	ContentClassBinaryELF          ContentClass = "binary_elf"
	ContentClassBinarySharedObject ContentClass = "binary_shared_object"
	ContentClassBinaryNUL          ContentClass = "binary_nul"
	ContentClassBinaryLowPrintable ContentClass = "binary_low_printable"
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
}

type BlobOpener interface {
	OpenLayer(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error)
}

type OpenFunc func(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error)

func (f OpenFunc) OpenLayer(ctx context.Context, descriptor manifest.Descriptor) (io.ReadCloser, error) {
	return f(ctx, descriptor)
}

type State struct {
	final   map[string]Artifact
	deleted []Artifact
}

func NewState() *State {
	return &State{
		final: make(map[string]Artifact),
	}
}

func Replay(ctx context.Context, descriptors []manifest.Descriptor, maxFileBytes int64, opener BlobOpener) (ReplayResult, error) {
	if maxFileBytes <= 0 {
		maxFileBytes = 1 << 20
	}

	state := NewState()
	for _, descriptor := range descriptors {
		if manifest.IsForeignLayerMediaType(descriptor.MediaType) {
			return ReplayResult{}, fmt.Errorf("foreign layer media type is not supported: %s", descriptor.MediaType)
		}
		if !manifest.IsLayerMediaType(descriptor.MediaType) {
			return ReplayResult{}, fmt.Errorf("unsupported layer media type: %s", descriptor.MediaType)
		}

		stream, err := opener.OpenLayer(ctx, descriptor)
		if err != nil {
			return ReplayResult{}, fmt.Errorf("open layer %s: %w", descriptor.Digest, err)
		}

		if err := state.applyLayer(descriptor, stream, maxFileBytes); err != nil {
			stream.Close()
			return ReplayResult{}, fmt.Errorf("apply layer %s: %w", descriptor.Digest, err)
		}
		stream.Close()
	}

	return ReplayResult{
		FinalFiles:       state.FinalFiles(),
		DeletedArtifacts: state.DeletedArtifacts(),
	}, nil
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

func (s *State) applyLayer(descriptor manifest.Descriptor, blob io.Reader, maxFileBytes int64) error {
	reader, cleanup, err := decompressLayer(descriptor.MediaType, blob)
	if err != nil {
		return err
	}
	defer cleanup()

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		entryPath, err := normalizePath(header.Name)
		if err != nil {
			continue
		}

		if isOpaqueWhiteout(entryPath) {
			s.deletePrefix(path.Dir(entryPath), descriptor.Digest)
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			continue
		}
		if isWhiteout(entryPath) {
			s.deletePath(whiteoutTarget(entryPath), descriptor.Digest)
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
		case tar.TypeSymlink:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			s.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeSymlink,
				Linkname:     strings.TrimSpace(header.Linkname),
				ContentClass: "",
				Scannable:    false,
			})
		case tar.TypeLink:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
			linkTarget, err := normalizePath(header.Linkname)
			if err != nil {
				continue
			}
			target, ok := s.final[linkTarget]
			if !ok {
				continue
			}
			copyContent := append([]byte(nil), target.Content...)
			s.put(Artifact{
				Path:         entryPath,
				LayerDigest:  descriptor.Digest,
				Type:         ArtifactTypeHardlink,
				Linkname:     linkTarget,
				Content:      copyContent,
				Size:         target.Size,
				ContentClass: target.ContentClass,
				Scannable:    target.Scannable,
			})
		case tar.TypeReg, tar.TypeRegA:
			artifact, err := buildRegularArtifact(entryPath, descriptor.Digest, tarReader, header.Size, maxFileBytes)
			if err != nil {
				return err
			}
			s.put(artifact)
		default:
			if err := drainEntry(tarReader); err != nil {
				return err
			}
		}
	}
}

func (s *State) put(artifact Artifact) {
	if current, ok := s.final[artifact.Path]; ok {
		current.DeletedByLayerDigest = artifact.LayerDigest
		if current.Type == ArtifactTypeRegularFile || current.Type == ArtifactTypeHardlink {
			s.deleted = append(s.deleted, current)
		}
	}
	s.final[artifact.Path] = artifact
}

func (s *State) deletePath(targetPath, deletedBy string) {
	current, ok := s.final[targetPath]
	if !ok {
		return
	}

	delete(s.final, targetPath)
	current.DeletedByLayerDigest = deletedBy
	if current.Type == ArtifactTypeRegularFile || current.Type == ArtifactTypeHardlink {
		s.deleted = append(s.deleted, current)
	}
}

func (s *State) deletePrefix(directoryPath, deletedBy string) {
	directoryPath = strings.Trim(strings.TrimSpace(directoryPath), "/")
	prefix := ""
	if directoryPath != "" && directoryPath != "." {
		prefix = directoryPath + "/"
	}

	keys := make([]string, 0)
	for key := range s.final {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	for _, key := range keys {
		s.deletePath(key, deletedBy)
	}
}

func buildRegularArtifact(entryPath, layerDigest string, reader io.Reader, size, maxFileBytes int64) (Artifact, error) {
	limited := io.LimitReader(reader, maxFileBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return Artifact{}, fmt.Errorf("read layer file %s: %w", entryPath, err)
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
		return Artifact{}, fmt.Errorf("discard remaining file bytes for %s: %w", entryPath, err)
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
	base := path.Base(strings.TrimSpace(entryPath))
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
			gzipReader.Close()
		}, nil
	case "zstd":
		decoder, err := zstd.NewReader(reader)
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

func normalizePath(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("path is required")
	}

	cleaned := strings.TrimPrefix(path.Clean("/"+trimmed), "/")
	if cleaned == "" || cleaned == "." {
		return "", fmt.Errorf("path is required")
	}

	return cleaned, nil
}

func isWhiteout(entryPath string) bool {
	base := path.Base(entryPath)
	return strings.HasPrefix(base, ".wh.") && base != ".wh..wh..opq"
}

func isOpaqueWhiteout(entryPath string) bool {
	return path.Base(entryPath) == ".wh..wh..opq"
}

func whiteoutTarget(entryPath string) string {
	base := strings.TrimPrefix(path.Base(entryPath), ".wh.")
	target := path.Join(path.Dir(entryPath), base)
	if target == "." {
		return base
	}
	return strings.TrimPrefix(path.Clean(target), "/")
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
