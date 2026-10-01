// Package source reads container images from the local filesystem and serves
// them through the same operations the registry client offers, so the scanner
// treats an OCI image layout directory (oci:), a tar archive of one
// (oci-archive:) or a `docker save` archive (docker-archive:) exactly like a
// registry repository.
//
// Local input is handled as hostile data even though the operator chose the
// path: every manifest and index read is bounded by Options.MaxManifestBytes,
// a tar archive is indexed once with bounded entry counts and path lengths and
// never extracted to disk, entry names with traversal or absolute paths make
// the archive unusable, symbolic and hard links inside an archive are never
// followed, a layout directory is opened as an os.Root so a symlink cannot
// point outside it, and every blob the scanner reads goes through
// manifest.NewVerifyingReader (digest and size) exactly as a registry blob
// does. Blob sizes are reported from the file or archive entry so the
// scanner's descriptor_size_mismatch check runs before a byte is hashed.
package source

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// Options bounds the reads a local source performs.
type Options struct {
	// MaxManifestBytes bounds every document read: index.json, oci-layout,
	// nested manifests, manifest.json and repositories. Zero or negative
	// means DefaultMaxManifestBytes.
	MaxManifestBytes int64
	// MaxArchiveEntries bounds the number of entries indexed in a tar
	// archive. Zero or negative means DefaultMaxArchiveEntries.
	MaxArchiveEntries int
	// MaxImageLayers bounds the layer list of one docker save image, which is
	// refused with the scanner's image_layers limit kind before any of it is
	// hashed. Zero or negative means no bound, as LAYERLEAK_MAX_IMAGE_LAYERS=0
	// does for the scanner.
	MaxImageLayers int
}

const (
	// DefaultMaxManifestBytes matches the registry client's default
	// LAYERLEAK_MAX_MANIFEST_BYTES.
	DefaultMaxManifestBytes int64 = 8 << 20
	// DefaultMaxArchiveEntries is generous for an image archive, which holds
	// a few files per layer, while keeping the in-memory index small.
	DefaultMaxArchiveEntries = 16384
	// maxArchiveEntryPathBytes bounds one entry name in the archive index.
	// Layout and docker-save paths are under 100 bytes.
	maxArchiveEntryPathBytes = 1024
	// maxListedTags bounds the tag names quoted in a selection error.
	maxListedTags = 20
)

// Source is a local scanner.BlobSource. Close releases the directory or
// archive handle; the source must not be used afterwards.
type Source interface {
	FetchManifest(ctx context.Context, repository, identifier string) (registry.ManifestResponse, error)
	ResolveManifest(ctx context.Context, repository, identifier string) (registry.ManifestMetadata, error)
	OpenBlob(ctx context.Context, repository, digest string) (registry.BlobResponse, error)
	ListTags(ctx context.Context, repository string, pageSize, maxTags int) ([]string, error)
	Close() error
}

// Open opens the local source a reference names. The reference must come from
// manifest.ParseLocalReference; its Repository is the scheme and path.
func Open(reference manifest.Reference, options Options) (Source, error) {
	if !reference.IsLocal() {
		return nil, fmt.Errorf("reference %s is not a local image source", reference.Original)
	}
	options = options.withDefaults()
	path := strings.TrimPrefix(reference.Repository, reference.Scheme+":")
	if path == "" {
		return nil, fmt.Errorf("local image reference requires a path")
	}
	switch reference.Scheme {
	case manifest.SchemeOCILayout:
		return openLayoutDirectory(path, options)
	case manifest.SchemeOCIArchive:
		return openLayoutArchive(path, options)
	case manifest.SchemeDockerArchive:
		return openDockerArchive(path, options)
	default:
		return nil, fmt.Errorf("unsupported local image source scheme %q", reference.Scheme)
	}
}

func (o Options) withDefaults() Options {
	if o.MaxManifestBytes <= 0 {
		o.MaxManifestBytes = DefaultMaxManifestBytes
	}
	if o.MaxArchiveEntries <= 0 {
		o.MaxArchiveEntries = DefaultMaxArchiveEntries
	}
	return o
}

// readDocument reads a whole document, refusing one larger than maxBytes
// with limits.KindManifestBytes before more than maxBytes+1 bytes are held.
func readDocument(reader io.Reader, maxBytes int64, subject string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limits.OverflowProbeLimit(maxBytes)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", subject, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, limits.NewExceeded(limits.KindManifestBytes, maxBytes, subject)
	}
	return body, nil
}

// declaredMediaType returns the media type a manifest or index body declares.
// The scanner refuses a root document whose declared and reported media types
// differ, so a source reports the declared one when no descriptor names it.
func declaredMediaType(body []byte, fallback string) (string, error) {
	document, err := manifest.ParseDocument(fallback, body)
	if err != nil {
		return "", err
	}
	if document.Kind == manifest.DocumentKindIndex {
		return document.Index.MediaType, nil
	}
	return document.Manifest.MediaType, nil
}

// boundedTags sorts and deduplicates tags and applies the sweep tag limit.
func boundedTags(tags []string, maxTags int, subject string) ([]string, error) {
	unique := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		unique = append(unique, tag)
	}
	sort.Strings(unique)
	if maxTags > 0 && len(unique) > maxTags {
		return unique[:maxTags], limits.NewExceeded(limits.KindRepositoryTags, int64(maxTags), subject)
	}
	return unique, nil
}

// describeTags lists tags for an error message, truncated so a hostile index
// cannot turn the message into a dump.
func describeTags(tags []string) string {
	if len(tags) == 0 {
		return "none"
	}
	sorted := append([]string(nil), tags...)
	sort.Strings(sorted)
	if len(sorted) > maxListedTags {
		return strings.Join(sorted[:maxListedTags], ", ") + fmt.Sprintf(" and %d more", len(sorted)-maxListedTags)
	}
	return strings.Join(sorted, ", ")
}

// sizedReadCloser is a blob body with a known size.
type sizedReadCloser interface {
	io.ReadCloser
	Size() int64
}

// sectionReadCloser serves one archive entry; Close is a no-op because the
// archive file stays open for the lifetime of the source.
type sectionReadCloser struct {
	*io.SectionReader
}

func (sectionReadCloser) Close() error { return nil }

// fileReadCloser serves one regular file of a layout directory.
type fileReadCloser struct {
	io.ReadCloser
	size int64
}

func (f fileReadCloser) Size() int64 { return f.size }

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// contextReader checks the context before every read, so a long stream stops
// within one read of the context ending.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (c contextReader) Read(buffer []byte) (int, error) {
	if err := contextError(c.ctx); err != nil {
		return 0, err
	}
	return c.reader.Read(buffer)
}
