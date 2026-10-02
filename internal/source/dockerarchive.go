package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

const (
	dockerManifestName     = "manifest.json"
	dockerRepositoriesName = "repositories"
	// hashChunkBytes is the read size while an archive entry is hashed; the
	// context is checked before every chunk.
	hashChunkBytes = 256 << 10
	// minLayerDescriptorJSONBytes is a lower bound on the encoded size of one
	// layer descriptor in a synthesised manifest: the shortest layer media
	// type alone is 43 bytes and a sha256 digest 71. It lets a layer list
	// whose manifest could never fit MaxManifestBytes be refused before any
	// layer is hashed.
	minLayerDescriptorJSONBytes = 100
)

// dockerManifestEntry is one image of a `docker save` manifest.json.
type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// dockerImage is the OCI view of one manifest.json entry: a synthesised image
// manifest whose config and layer descriptors name the archive entries by the
// digest of their bytes.
type dockerImage struct {
	digest string
	body   []byte
	blobs  map[string]string // blob digest -> archive entry name
}

// dockerArchive serves a `docker save` archive as a BlobSource. The archive
// has no manifests in registry form, so one is synthesised per image from
// manifest.json; its digest is the image's resolved digest and every blob is
// still verified by the scanner against the digest computed here.
type dockerArchive struct {
	location     string
	archive      *tarIndex
	options      Options
	entries      []dockerManifestEntry
	repositories map[string]map[string]string

	mu     sync.Mutex
	images map[int]*dockerImage
	blobs  map[string]string
	// hashed memoises the hash of every archive entry by clean name, across
	// all images, so an entry referenced many times is read once.
	hashed map[string]hashedEntry
	// hashedEntries counts the entries actually read and hashed.
	hashedEntries int
	hashBuffer    []byte
}

// hashedEntry is what hashing an archive entry learns: its digest, its size
// and the layer media type its first bytes indicate.
type hashedEntry struct {
	digest         string
	size           int64
	layerMediaType string
}

func openDockerArchive(archivePath string, options Options) (Source, error) {
	index, err := openTarIndex(archivePath, options.MaxArchiveEntries)
	if err != nil {
		return nil, fmt.Errorf("open docker archive: %w", err)
	}
	source, err := newDockerArchive(archivePath, index, options)
	if err != nil {
		_ = index.Close()
		return nil, err
	}
	return source, nil
}

func newDockerArchive(location string, index *tarIndex, options Options) (*dockerArchive, error) {
	body, err := index.readAll(dockerManifestName, options.MaxManifestBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			hint := ""
			if _, isLayout := index.lookup(layoutIndexName); isLayout {
				hint = "; it looks like an OCI layout archive, use oci-archive:" + location
			}
			return nil, fmt.Errorf("docker archive %s has no %s%s", location, dockerManifestName, hint)
		}
		return nil, fmt.Errorf("docker archive %s: %w", location, err)
	}
	var entries []dockerManifestEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("docker archive %s: decode %s: %w", location, dockerManifestName, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("docker archive %s: %s lists no images", location, dockerManifestName)
	}
	for index, entry := range entries {
		if strings.TrimSpace(entry.Config) == "" {
			return nil, fmt.Errorf("docker archive %s: image %d has no config", location, index)
		}
	}

	source := &dockerArchive{location: location, archive: index, options: options, entries: entries, images: make(map[int]*dockerImage), blobs: make(map[string]string), hashed: make(map[string]hashedEntry)}
	if repositoriesBody, err := index.readAll(dockerRepositoriesName, options.MaxManifestBytes); err == nil {
		// The legacy repositories map is optional; a malformed one is ignored
		// because manifest.json is authoritative.
		_ = json.Unmarshal(repositoriesBody, &source.repositories)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("docker archive %s: %w", location, err)
	}
	return source, nil
}

// entryTags returns the image names of one manifest.json entry: its RepoTags,
// or, for an archive without RepoTags, the repositories map entries whose
// layer id is the entry's top layer directory.
func (d *dockerArchive) entryTags(index int) []string {
	entry := d.entries[index]
	tags := make([]string, 0, len(entry.RepoTags))
	for _, tag := range entry.RepoTags {
		if tag = strings.TrimSpace(tag); tag != "" {
			tags = append(tags, tag)
		}
	}
	if len(tags) > 0 || len(entry.Layers) == 0 {
		return tags
	}
	topLayer := path.Dir(path.Clean(entry.Layers[len(entry.Layers)-1]))
	for repository, byTag := range d.repositories {
		for tag, layerID := range byTag {
			if layerID == topLayer && repository != "" && tag != "" {
				tags = append(tags, repository+":"+tag)
			}
		}
	}
	return tags
}

func (d *dockerArchive) allTags() []string {
	tags := make([]string, 0)
	for index := range d.entries {
		tags = append(tags, d.entryTags(index)...)
	}
	return tags
}

// normalizeImageName brings `alpine:3.20`, `library/alpine:3.20` and
// `docker.io/library/alpine` to one form so the caller's name matches the
// RepoTags spelling `docker save` wrote; an unparsable name compares as is.
func normalizeImageName(name string) string {
	reference, err := manifest.ParseReference(name)
	if err != nil {
		return name
	}
	if reference.Tag == "" && reference.Digest == "" {
		reference.Tag = "latest"
	}
	return reference.String()
}

// selectImage resolves an identifier to a manifest.json entry: the only entry
// for "", the entry carrying the image name, or the entry whose synthesised
// manifest has the digest (images over a configured limit are skipped).
func (d *dockerArchive) selectImage(ctx context.Context, identifier string) (*dockerImage, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		if len(d.entries) != 1 {
			return nil, fmt.Errorf("docker archive %s holds %d images; select one with :<repo:tag> (available: %s) or @<digest>", d.location, len(d.entries), describeTags(d.allTags()))
		}
		return d.image(ctx, 0)
	}
	if manifest.ValidateDigest(identifier) == nil {
		return d.selectImageByDigest(ctx, identifier)
	}
	return d.selectImageByName(ctx, identifier)
}

// selectImageByDigest returns the image whose synthesised manifest has the
// digest. An image over a configured limit has no synthesised manifest and so
// no digest; it is skipped so an unrelated oversize image cannot make the
// others unselectable, and the limit is reported only when nothing matches.
func (d *dockerArchive) selectImageByDigest(ctx context.Context, identifier string) (*dockerImage, error) {
	var skipped error
	for index := range d.entries {
		image, err := d.image(ctx, index)
		if err != nil {
			if limits.IsExceeded(err) {
				if skipped == nil {
					skipped = err
				}
				continue
			}
			return nil, err
		}
		if image.digest == identifier {
			return image, nil
		}
	}
	if skipped != nil {
		return nil, fmt.Errorf("docker archive %s has no in-limit image with digest %s: %w", d.location, identifier, skipped)
	}
	return nil, fmt.Errorf("docker archive %s has no image with digest %s", d.location, identifier)
}

// selectImageByName returns the one image carrying the name, compared after
// normalizeImageName.
func (d *dockerArchive) selectImageByName(ctx context.Context, identifier string) (*dockerImage, error) {
	wanted := normalizeImageName(identifier)
	matches := make([]int, 0, 1)
	for index := range d.entries {
		for _, tag := range d.entryTags(index) {
			if normalizeImageName(tag) == wanted {
				matches = append(matches, index)
				break
			}
		}
	}
	switch len(matches) {
	case 1:
		return d.image(ctx, matches[0])
	case 0:
		return nil, fmt.Errorf("docker archive %s has no image named %q (available: %s)", d.location, identifier, describeTags(d.allTags()))
	default:
		return nil, fmt.Errorf("docker archive %s names %d images %q; select one with @<digest>", d.location, len(matches), identifier)
	}
}

// image builds (once) the OCI view of a manifest.json entry. Building hashes
// the config and every distinct layer entry of that image, streaming from the
// archive and stopping when ctx ends. A layer list longer than
// Options.MaxImageLayers, or one whose manifest could not fit
// Options.MaxManifestBytes, is refused before anything is hashed.
func (d *dockerArchive) image(ctx context.Context, index int) (*dockerImage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if image, ok := d.images[index]; ok {
		return image, nil
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	entry := d.entries[index]
	if err := d.checkLayerCount(index, len(entry.Layers)); err != nil {
		return nil, err
	}
	blobs := make(map[string]string, len(entry.Layers)+1)

	configDescriptor, err := d.describeConfig(ctx, index, entry.Config, blobs)
	if err != nil {
		return nil, err
	}
	layers, err := d.describeLayers(ctx, index, entry.Layers, blobs)
	if err != nil {
		return nil, err
	}

	body, digest, err := d.encodeImageManifest(index, configDescriptor, layers)
	if err != nil {
		return nil, err
	}
	image := &dockerImage{digest: digest, body: body, blobs: blobs}
	d.images[index] = image
	for blobDigest, name := range blobs {
		d.blobs[blobDigest] = name
	}
	return image, nil
}

// checkLayerCount refuses a layer list longer than Options.MaxImageLayers, or
// one whose manifest could not fit Options.MaxManifestBytes, before anything
// is hashed.
func (d *dockerArchive) checkLayerCount(index, layerCount int) error {
	if d.options.MaxImageLayers > 0 && layerCount > d.options.MaxImageLayers {
		return fmt.Errorf("docker archive %s: image %d: %w", d.location, index, limits.NewExceeded(limits.Kind("image_layers"), int64(d.options.MaxImageLayers), "image manifest"))
	}
	if int64(layerCount) > d.options.MaxManifestBytes/minLayerDescriptorJSONBytes {
		return fmt.Errorf("docker archive %s: image %d: %w", d.location, index, limits.NewExceeded(limits.KindManifestBytes, d.options.MaxManifestBytes, "synthesised image manifest"))
	}
	return nil
}

// describeConfig hashes the config entry of an image and records it in blobs.
// The caller holds d.mu.
func (d *dockerArchive) describeConfig(ctx context.Context, index int, configPath string, blobs map[string]string) (manifest.Descriptor, error) {
	configName, err := cleanArchivePath(configPath)
	if err != nil {
		return manifest.Descriptor{}, fmt.Errorf("docker archive %s: image %d config: %w", d.location, index, err)
	}
	configDescriptor, err := d.describeEntry(ctx, configName, manifest.MediaTypeDockerContainerConfig)
	if err != nil {
		return manifest.Descriptor{}, fmt.Errorf("docker archive %s: image %d config: %w", d.location, index, err)
	}
	blobs[configDescriptor.Digest] = configName
	return configDescriptor, nil
}

// describeLayers hashes the layer entries of an image in order and records
// them in blobs. Two different entries with the same digest are refused. The
// caller holds d.mu.
func (d *dockerArchive) describeLayers(ctx context.Context, index int, layerPaths []string, blobs map[string]string) ([]manifest.Descriptor, error) {
	layers := make([]manifest.Descriptor, 0, len(layerPaths))
	for position, layerPath := range layerPaths {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		layerName, err := cleanArchivePath(layerPath)
		if err != nil {
			return nil, fmt.Errorf("docker archive %s: image %d layer %d: %w", d.location, index, position, err)
		}
		descriptor, err := d.describeEntry(ctx, layerName, "")
		if err != nil {
			return nil, fmt.Errorf("docker archive %s: image %d layer %d: %w", d.location, index, position, err)
		}
		if existing, ok := blobs[descriptor.Digest]; ok && existing != layerName {
			return nil, fmt.Errorf("docker archive %s: image %d: entries %s and %s have the same digest", d.location, index, existing, layerName)
		}
		blobs[descriptor.Digest] = layerName
		layers = append(layers, descriptor)
	}
	return layers, nil
}

// encodeImageManifest encodes the synthesised image manifest, refuses one
// over Options.MaxManifestBytes and returns it with its digest.
func (d *dockerArchive) encodeImageManifest(index int, configDescriptor manifest.Descriptor, layers []manifest.Descriptor) ([]byte, string, error) {
	body, err := json.Marshal(manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeDockerSchema2Manifest,
		Config:        configDescriptor,
		Layers:        layers,
	})
	if err != nil {
		return nil, "", fmt.Errorf("docker archive %s: encode manifest: %w", d.location, err)
	}
	if int64(len(body)) > d.options.MaxManifestBytes {
		return nil, "", fmt.Errorf("docker archive %s: image %d: %w", d.location, index, limits.NewExceeded(limits.KindManifestBytes, d.options.MaxManifestBytes, "synthesised image manifest"))
	}
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		return nil, "", err
	}
	return body, digest, nil
}

// describeEntry returns the descriptor of one archive entry, hashing it the
// first time any image names it. An empty media type means a layer, whose
// compression is sniffed from the first bytes. The caller holds d.mu.
func (d *dockerArchive) describeEntry(ctx context.Context, name, mediaType string) (manifest.Descriptor, error) {
	hashed, ok := d.hashed[name]
	if !ok {
		var err error
		hashed, err = d.hashEntry(ctx, name)
		if err != nil {
			return manifest.Descriptor{}, err
		}
		d.hashed[name] = hashed
	}
	if mediaType == "" {
		mediaType = hashed.layerMediaType
	}
	return manifest.Descriptor{MediaType: mediaType, Digest: hashed.digest, Size: hashed.size}, nil
}

// hashEntry streams one archive entry through SHA-256, checking ctx before
// every chunk so a deadline stops it mid-entry. The caller holds d.mu.
func (d *dockerArchive) hashEntry(ctx context.Context, name string) (hashedEntry, error) {
	body, err := d.archive.open(name)
	if err != nil {
		return hashedEntry{}, err
	}
	defer func() { _ = body.Close() }()
	d.hashedEntries++
	reader := contextReader{ctx: ctx, reader: body}
	hasher := sha256.New()
	head := make([]byte, 4)
	headLength, err := io.ReadFull(reader, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return hashedEntry{}, fmt.Errorf("read %s: %w", name, err)
	}
	_, _ = hasher.Write(head[:headLength])
	if d.hashBuffer == nil {
		d.hashBuffer = make([]byte, hashChunkBytes)
	}
	if _, err := io.CopyBuffer(hasher, reader, d.hashBuffer); err != nil {
		return hashedEntry{}, fmt.Errorf("read %s: %w", name, err)
	}
	return hashedEntry{
		digest:         "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		size:           body.Size(),
		layerMediaType: layerMediaTypeFor(head[:headLength]),
	}, nil
}

// layerMediaTypeFor picks the layer media type from the magic bytes: docker
// save writes uncompressed tars, but gzip and zstd members are recognised.
func layerMediaTypeFor(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return manifest.MediaTypeDockerSchema2LayerGzip
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return manifest.MediaTypeOCIImageLayerZstd
	default:
		return manifest.MediaTypeDockerSchema2Layer
	}
}

func (d *dockerArchive) FetchManifest(ctx context.Context, _, identifier string) (registry.ManifestResponse, error) {
	if err := contextError(ctx); err != nil {
		return registry.ManifestResponse{}, err
	}
	image, err := d.selectImage(ctx, identifier)
	if err != nil {
		return registry.ManifestResponse{}, err
	}
	return registry.ManifestResponse{Digest: image.digest, MediaType: manifest.MediaTypeDockerSchema2Manifest, Size: int64(len(image.body)), Body: image.body}, nil
}

func (d *dockerArchive) ResolveManifest(ctx context.Context, _, identifier string) (registry.ManifestMetadata, error) {
	if err := contextError(ctx); err != nil {
		return registry.ManifestMetadata{}, err
	}
	image, err := d.selectImage(ctx, identifier)
	if err != nil {
		return registry.ManifestMetadata{}, err
	}
	return registry.ManifestMetadata{Digest: image.digest, MediaType: manifest.MediaTypeDockerSchema2Manifest}, nil
}

func (d *dockerArchive) OpenBlob(ctx context.Context, _, digest string) (registry.BlobResponse, error) {
	if err := contextError(ctx); err != nil {
		return registry.BlobResponse{}, err
	}
	if err := manifest.ValidateDigest(digest); err != nil {
		return registry.BlobResponse{}, fmt.Errorf("validate blob digest: %w", err)
	}
	d.mu.Lock()
	name, ok := d.blobs[digest]
	d.mu.Unlock()
	if !ok {
		return registry.BlobResponse{}, fmt.Errorf("docker archive %s: blob %s is not in the archive", d.location, digest)
	}
	body, err := d.archive.open(name)
	if err != nil {
		return registry.BlobResponse{}, fmt.Errorf("docker archive %s: open blob %s: %w", d.location, digest, err)
	}
	return registry.BlobResponse{Digest: digest, Size: body.Size(), Body: body}, nil
}

func (d *dockerArchive) ListTags(ctx context.Context, _ string, _, maxTags int) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return boundedTags(d.allTags(), maxTags, "docker archive "+d.location)
}

func (d *dockerArchive) Close() error {
	return d.archive.Close()
}
