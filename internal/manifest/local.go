package manifest

import (
	"fmt"
	"strings"
	"unicode"

	distributionreference "github.com/distribution/reference"
)

// Local image source schemes. A reference that starts with one of them
// (followed by a colon) names an image on the local filesystem instead of a
// registry; see ParseLocalReference for the grammar.
const (
	// SchemeOCILayout names an OCI image layout directory: oci:/path[:tag|@digest].
	SchemeOCILayout = "oci"
	// SchemeOCIArchive names a tar archive of an OCI image layout:
	// oci-archive:/file.tar[:tag|@digest].
	SchemeOCIArchive = "oci-archive"
	// SchemeDockerArchive names a `docker save` archive:
	// docker-archive:/file.tar[:repo[:tag]|@digest].
	SchemeDockerArchive = "docker-archive"
)

// LocalRegistry is the Registry of every local reference. It cannot collide
// with a real registry: a bare host without a dot or port is never a registry
// in the reference grammar (`local/app` is docker.io/local/app).
const LocalRegistry = "local"

// ErrLocalSourceNotSupported is returned by ParseReference for a reference
// that names a local image source. Local sources are a CLI feature; the HTTP
// API relays this message as an invalid_request error.
var ErrLocalSourceNotSupported = fmt.Errorf("local image sources (oci:, oci-archive:, docker-archive:) are only supported by the layerleak CLI; provide a registry image reference")

var localSchemes = []string{SchemeOCILayout, SchemeOCIArchive, SchemeDockerArchive}

// LocalScheme returns the local source scheme raw starts with, or "" when
// raw is not a local reference. Schemes are matched case-insensitively and
// must be followed by a colon. `oci:5000/app` stays a registry reference
// (host oci, port 5000): a scheme followed by a port and a slash is not a
// local source.
func LocalScheme(raw string) string {
	for _, scheme := range localSchemes {
		if len(raw) > len(scheme) && raw[len(scheme)] == ':' && strings.EqualFold(raw[:len(scheme)], scheme) {
			if looksLikePort(raw[len(scheme)+1:]) {
				return ""
			}
			return scheme
		}
	}
	return ""
}

// looksLikePort reports whether value starts with a decimal port followed by
// a slash, the shape of a host:port/repository registry reference.
func looksLikePort(value string) bool {
	digits := 0
	for digits < len(value) && value[digits] >= '0' && value[digits] <= '9' {
		digits++
	}
	return digits > 0 && digits <= 5 && digits < len(value) && value[digits] == '/'
}

// IsLocal reports whether the reference names a local image source.
func (r Reference) IsLocal() bool {
	return r.Scheme != ""
}

// ParseImageReference parses a command-line image reference: a local source
// reference when raw starts with a local scheme, otherwise a registry
// reference (ParseReference).
func ParseImageReference(raw string) (Reference, error) {
	if LocalScheme(raw) != "" {
		return ParseLocalReference(raw)
	}
	return ParseReference(raw)
}

// ParseLocalReference parses a local image source reference:
//
//	oci:<path>[:<tag>][@<digest>]
//	oci-archive:<path>[:<tag>][@<digest>]
//	docker-archive:<path>[:<repo>[:<tag>]][@<digest>]
//
// <path> is the layout directory or archive file, absolute or relative to
// the working directory, kept exactly as written. For oci: and oci-archive:
// the tag is the text after the last colon when that text contains no path
// separator (so `oci:./images/app:1.2` selects the ref.name `1.2` and
// `oci:/srv/a:b/c` is a path); it must be a valid OCI tag. For
// docker-archive: the path ends at the first colon and the rest is the
// `repo[:tag]` image name recorded by `docker save` (`alpine:3.20`,
// `ghcr.io/org/app`), so a docker-archive path cannot contain a colon. A
// digest after `@` selects the manifest with that digest in any scheme.
//
// Repository is the scheme and path (`oci:/srv/images/app`), Registry is
// LocalRegistry, and Tag or Digest carry the selection. Surrounding
// whitespace and control characters are rejected.
func ParseLocalReference(raw string) (Reference, error) {
	scheme := LocalScheme(raw)
	if scheme == "" {
		return Reference{}, fmt.Errorf("local image reference must start with an oci:, oci-archive: or docker-archive: scheme")
	}
	if raw != strings.TrimSpace(raw) {
		return Reference{}, fmt.Errorf("local image reference must not include surrounding whitespace")
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return Reference{}, fmt.Errorf("local image reference contains control characters")
	}
	rest := raw[len(scheme)+1:]

	digest := ""
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		digest = rest[at+1:]
		rest = rest[:at]
		if err := ValidateDigest(digest); err != nil {
			return Reference{}, err
		}
	}
	if strings.Count(rest, "@") > 0 {
		return Reference{}, fmt.Errorf("local image reference must contain at most one digest separator")
	}

	var path, tag string
	var err error
	switch scheme {
	case SchemeDockerArchive:
		path, tag, err = splitDockerArchiveReference(rest)
	default:
		path, tag, err = splitLayoutReference(rest)
	}
	if err != nil {
		return Reference{}, err
	}
	if path == "" {
		return Reference{}, fmt.Errorf("local image reference requires a path after the %s: scheme", scheme)
	}

	return Reference{
		Original:    raw,
		Scheme:      scheme,
		Registry:    LocalRegistry,
		Repository:  scheme + ":" + path,
		Tag:         tag,
		Digest:      digest,
		TagExplicit: tag != "",
	}, nil
}

// splitLayoutReference splits path[:tag] for the oci: and oci-archive:
// schemes: the text after the last colon is the tag unless it contains a
// path separator, in which case the whole value is the path.
func splitLayoutReference(value string) (string, string, error) {
	colon := strings.LastIndexByte(value, ':')
	if colon < 0 {
		return value, "", nil
	}
	candidate := value[colon+1:]
	if strings.ContainsAny(candidate, `/\`) {
		return value, "", nil
	}
	if !isValidLocalTag(candidate) {
		return "", "", fmt.Errorf("local image reference has an invalid tag after the last colon")
	}
	return value[:colon], candidate, nil
}

// splitDockerArchiveReference splits path[:repo[:tag]] for docker-archive:
// the path ends at the first colon and the remainder must be a registry-style
// image name without a digest, as `docker save` records it in RepoTags.
func splitDockerArchiveReference(value string) (string, string, error) {
	colon := strings.IndexByte(value, ':')
	if colon < 0 {
		return value, "", nil
	}
	name := value[colon+1:]
	if name == "" {
		return "", "", fmt.Errorf("docker-archive reference has an empty image name after the path")
	}
	parsed, err := ParseReference(name)
	if err != nil {
		return "", "", fmt.Errorf("docker-archive image name %w", err)
	}
	if parsed.Digest != "" {
		return "", "", fmt.Errorf("docker-archive image name must not carry a digest; use @digest after the path")
	}
	return value[:colon], name, nil
}

func isValidLocalTag(tag string) bool {
	return tag != "" && distributionreference.TagRegexp.FindString(tag) == tag
}
