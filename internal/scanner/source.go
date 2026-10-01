package scanner

import (
	"context"

	"github.com/brumbelow/layerleak/v3/internal/registry"
)

// BlobSource is where a scan reads an image from: the root manifest by tag or
// digest, the image manifests and blobs it references by digest, and, for
// repository sweeps, the tags the repository holds. *registry.Client is the
// network implementation; the local readers in internal/source serve the
// same operations from an OCI image layout directory, an OCI archive or a
// `docker save` archive.
//
// The repository argument is the Reference.Repository of the scan; a local
// source ignores it because it serves exactly one repository. Every blob body
// is wrapped in manifest.NewVerifyingReader by the scanner, and manifest
// bodies are checked against the expected digest before they are decoded, so
// an implementation only has to return the bytes and whatever digest and size
// it knows (both may be left empty). A manifest response must carry the media
// type the document declares, because the scanner refuses a root document
// whose declared and reported media types differ; a blob response may leave
// MediaType empty.
type BlobSource interface {
	// FetchManifest returns the manifest named by identifier: a tag, a digest
	// or, for a local source, the empty string for the only image it holds.
	FetchManifest(ctx context.Context, repository, identifier string) (registry.ManifestResponse, error)
	// ResolveManifest returns the digest (and media type, when known) of the
	// manifest named by identifier without returning its body.
	ResolveManifest(ctx context.Context, repository, identifier string) (registry.ManifestMetadata, error)
	// OpenBlob opens the blob with the given digest. The caller closes Body.
	OpenBlob(ctx context.Context, repository, digest string) (registry.BlobResponse, error)
	// ListTags returns the sorted, unique tags of the repository, at most
	// maxTags of them when maxTags is positive (limits.KindRepositoryTags
	// when more exist). pageSize is a hint for paginated sources.
	ListTags(ctx context.Context, repository string, pageSize, maxTags int) ([]string, error)
}

// The registry client is the reference implementation of BlobSource.
var _ BlobSource = (*registry.Client)(nil)
