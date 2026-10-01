package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

const (
	layoutFileName  = "oci-layout"
	layoutIndexName = "index.json"
	layoutBlobsDir  = "blobs"
	// refNameAnnotation is the OCI image layout tag annotation.
	refNameAnnotation = "org.opencontainers.image.ref.name"
)

// layoutFS is the file access a layout reader needs: the two top-level
// documents and the blobs, by clean slash path relative to the layout root.
type layoutFS interface {
	open(name string) (sizedReadCloser, error)
	readAll(name string, maxBytes int64) ([]byte, error)
	Close() error
}

// layout serves an OCI image layout (directory or archive) as a BlobSource.
type layout struct {
	location string
	fs       layoutFS
	options  Options
	index    manifest.ImageIndex
}

// openLayoutDirectory opens an OCI image layout directory as an os.Root, so
// no symbolic link inside it can lead outside it.
func openLayoutDirectory(dir string, options Options) (Source, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout directory: %w", err)
	}
	source, err := newLayout(dir, &directoryFS{root: root}, options)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return source, nil
}

// openLayoutArchive opens a tar archive that holds an OCI image layout.
func openLayoutArchive(archivePath string, options Options) (Source, error) {
	index, err := openTarIndex(archivePath, options.MaxArchiveEntries)
	if err != nil {
		return nil, fmt.Errorf("open OCI archive: %w", err)
	}
	if _, ok := index.lookup(layoutIndexName); !ok {
		_ = index.Close()
		hint := ""
		if _, isDocker := index.lookup(dockerManifestName); isDocker {
			hint = "; it looks like a docker save archive, use docker-archive:" + archivePath
		}
		return nil, fmt.Errorf("OCI archive %s has no %s%s", archivePath, layoutIndexName, hint)
	}
	source, err := newLayout(archivePath, index, options)
	if err != nil {
		_ = index.Close()
		return nil, err
	}
	return source, nil
}

func newLayout(location string, fs layoutFS, options Options) (*layout, error) {
	layoutBody, err := fs.readAll(layoutFileName, options.MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("OCI layout %s: %w", location, err)
	}
	var layoutFile struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(layoutBody, &layoutFile); err != nil {
		return nil, fmt.Errorf("OCI layout %s: decode %s: %w", location, layoutFileName, err)
	}
	if !strings.HasPrefix(layoutFile.Version, "1.") {
		return nil, fmt.Errorf("OCI layout %s: unsupported imageLayoutVersion %q", location, layoutFile.Version)
	}

	indexBody, err := fs.readAll(layoutIndexName, options.MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("OCI layout %s: %w", location, err)
	}
	document, err := manifest.ParseDocument(manifest.MediaTypeOCIImageIndex, indexBody)
	if err != nil {
		return nil, fmt.Errorf("OCI layout %s: %s: %w", location, layoutIndexName, err)
	}
	if document.Kind != manifest.DocumentKindIndex {
		return nil, fmt.Errorf("OCI layout %s: %s is not an image index", location, layoutIndexName)
	}
	if err := manifest.ValidateImageIndex(document.Index); err != nil {
		return nil, fmt.Errorf("OCI layout %s: %s: %w", location, layoutIndexName, err)
	}
	return &layout{location: location, fs: fs, options: options, index: document.Index}, nil
}

// tags returns the ref.name annotation of every index entry that has one.
func (l *layout) tags() []string {
	tags := make([]string, 0, len(l.index.Manifests))
	for _, descriptor := range l.index.Manifests {
		if tag := strings.TrimSpace(descriptor.Annotations[refNameAnnotation]); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// selectDescriptor resolves an identifier to an index descriptor: the only
// entry for "", the entry whose ref.name annotation is the identifier, or the
// entry with that digest. A ref.name is matched exactly first; when nothing
// matches, ref.names that are image names (`docker.io/library/app:1.2`, as
// BuildKit writes for `-t app:1.2`) are matched by normalised image name so
// `app:1.2` selects that entry. Only an identifier that validates as a digest
// is a digest lookup, so a ref.name with a colon is never mistaken for one. A
// digest may name a manifest the index does not list (a platform manifest
// under a nested index); the descriptor then carries only the digest.
func (l *layout) selectDescriptor(identifier string) (manifest.Descriptor, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		if len(l.index.Manifests) != 1 {
			return manifest.Descriptor{}, fmt.Errorf("OCI layout %s holds %d images; select one with :<tag> (available: %s) or @<digest>", l.location, len(l.index.Manifests), describeTags(l.tags()))
		}
		return l.index.Manifests[0], nil
	}
	isDigest := manifest.ValidateDigest(identifier) == nil
	matches := l.descriptorsTagged(func(tag string) bool { return tag == identifier })
	if len(matches) == 0 && !isDigest {
		wanted := normalizeImageName(identifier)
		matches = l.descriptorsTagged(func(tag string) bool { return normalizeImageName(tag) == wanted })
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if isDigest {
			for _, descriptor := range l.index.Manifests {
				if descriptor.Digest == identifier {
					return descriptor, nil
				}
			}
			return manifest.Descriptor{Digest: identifier}, nil
		}
		return manifest.Descriptor{}, fmt.Errorf("OCI layout %s has no image tagged %q (available: %s)", l.location, identifier, describeTags(l.tags()))
	default:
		return manifest.Descriptor{}, fmt.Errorf("OCI layout %s tags %d images %q; select one with @<digest>", l.location, len(matches), identifier)
	}
}

// descriptorsTagged returns the index entries whose ref.name annotation
// satisfies match.
func (l *layout) descriptorsTagged(match func(tag string) bool) []manifest.Descriptor {
	var matches []manifest.Descriptor
	for _, descriptor := range l.index.Manifests {
		tag := strings.TrimSpace(descriptor.Annotations[refNameAnnotation])
		if tag != "" && match(tag) {
			matches = append(matches, descriptor)
		}
	}
	return matches
}

func blobPath(digest string) (string, error) {
	if err := manifest.ValidateDigest(digest); err != nil {
		return "", err
	}
	algorithm, encoded, _ := strings.Cut(digest, ":")
	return path.Join(layoutBlobsDir, algorithm, encoded), nil
}

func (l *layout) FetchManifest(ctx context.Context, _, identifier string) (registry.ManifestResponse, error) {
	if err := contextError(ctx); err != nil {
		return registry.ManifestResponse{}, err
	}
	descriptor, err := l.selectDescriptor(identifier)
	if err != nil {
		return registry.ManifestResponse{}, err
	}
	name, err := blobPath(descriptor.Digest)
	if err != nil {
		return registry.ManifestResponse{}, err
	}
	body, err := l.fs.readAll(name, l.options.MaxManifestBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return registry.ManifestResponse{}, fmt.Errorf("OCI layout %s: manifest %s is not in the layout", l.location, descriptor.Digest)
		}
		return registry.ManifestResponse{}, fmt.Errorf("OCI layout %s: %w", l.location, err)
	}
	if descriptor.Size > 0 && descriptor.Size != int64(len(body)) {
		return registry.ManifestResponse{}, &manifest.IntegrityError{Kind: manifest.IntegritySizeMismatch, Subject: descriptor.Digest, Expected: fmt.Sprintf("%d", descriptor.Size), Actual: fmt.Sprintf("%d", len(body))}
	}
	algorithm, _, _ := strings.Cut(descriptor.Digest, ":")
	actual, err := manifest.DigestBytes(algorithm, body)
	if err != nil {
		return registry.ManifestResponse{}, err
	}
	if actual != descriptor.Digest {
		return registry.ManifestResponse{}, &manifest.IntegrityError{Kind: manifest.IntegrityDigestMismatch, Subject: descriptor.Digest, Expected: descriptor.Digest, Actual: actual}
	}
	mediaType, err := declaredMediaType(body, descriptor.MediaType)
	if err != nil {
		return registry.ManifestResponse{}, &manifest.IntegrityError{Kind: manifest.IntegrityInvalidDocument, Subject: descriptor.Digest, Expected: "valid image manifest or index JSON", Actual: "invalid document", Cause: err}
	}
	return registry.ManifestResponse{Digest: descriptor.Digest, MediaType: mediaType, Size: int64(len(body)), Body: body}, nil
}

func (l *layout) ResolveManifest(ctx context.Context, _, identifier string) (registry.ManifestMetadata, error) {
	if err := contextError(ctx); err != nil {
		return registry.ManifestMetadata{}, err
	}
	descriptor, err := l.selectDescriptor(identifier)
	if err != nil {
		return registry.ManifestMetadata{}, err
	}
	return registry.ManifestMetadata{Digest: descriptor.Digest, MediaType: descriptor.MediaType}, nil
}

func (l *layout) OpenBlob(ctx context.Context, _, digest string) (registry.BlobResponse, error) {
	if err := contextError(ctx); err != nil {
		return registry.BlobResponse{}, err
	}
	name, err := blobPath(digest)
	if err != nil {
		return registry.BlobResponse{}, fmt.Errorf("validate blob digest: %w", err)
	}
	body, err := l.fs.open(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return registry.BlobResponse{}, fmt.Errorf("OCI layout %s: blob %s is not in the layout", l.location, digest)
		}
		return registry.BlobResponse{}, fmt.Errorf("OCI layout %s: open blob %s: %w", l.location, digest, err)
	}
	return registry.BlobResponse{Digest: digest, Size: body.Size(), Body: body}, nil
}

func (l *layout) ListTags(ctx context.Context, _ string, _, maxTags int) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return boundedTags(l.tags(), maxTags, "OCI layout "+l.location)
}

func (l *layout) Close() error {
	return l.fs.Close()
}

// directoryFS reads a layout directory through an os.Root.
type directoryFS struct {
	root *os.Root
}

func (d *directoryFS) open(name string) (sizedReadCloser, error) {
	file, err := d.root.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return fileReadCloser{ReadCloser: file, size: info.Size()}, nil
}

func (d *directoryFS) readAll(name string, maxBytes int64) ([]byte, error) {
	file, err := d.open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if file.Size() > maxBytes {
		return nil, limits.NewExceeded(limits.KindManifestBytes, maxBytes, name)
	}
	return readDocument(file, maxBytes, name)
}

func (d *directoryFS) Close() error {
	return d.root.Close()
}
