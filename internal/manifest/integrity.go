// Package manifest provides OCI manifest parsing and validation.
package manifest

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"strconv"
	"strings"
)

type IntegrityErrorKind string

const (
	IntegrityInvalidDocument            IntegrityErrorKind = "invalid_manifest_document"
	IntegrityInvalidDigest              IntegrityErrorKind = "invalid_descriptor_digest"
	IntegrityDigestMismatch             IntegrityErrorKind = "descriptor_digest_mismatch"
	IntegritySizeMismatch               IntegrityErrorKind = "descriptor_size_mismatch"
	IntegrityMediaTypeMismatch          IntegrityErrorKind = "descriptor_media_type_mismatch"
	IntegrityPlatformMismatch           IntegrityErrorKind = "descriptor_platform_mismatch"
	IntegrityUnsupportedDigestAlgorithm IntegrityErrorKind = "unsupported_digest_algorithm"
)

type IntegrityError struct {
	Kind     IntegrityErrorKind
	Subject  string
	Expected string
	Actual   string
	Cause    error
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf(
		"%s for %s: expected %s, got %s",
		e.Kind,
		safeIntegrityField(defaultIntegritySubject(e.Subject)),
		safeIntegrityField(e.Expected),
		safeIntegrityField(e.Actual),
	)
}

func (e *IntegrityError) Unwrap() error {
	return e.Cause
}

func IsIntegrityError(err error) bool {
	var target *IntegrityError
	return errors.As(err, &target)
}

func AsIntegrityError(err error) (*IntegrityError, bool) {
	var target *IntegrityError
	if !errors.As(err, &target) {
		return nil, false
	}
	return target, true
}

// DigestBytes calculates a supported OCI digest for body.
func DigestBytes(algorithm string, body []byte) (string, error) {
	hasher, err := newDigestHash(strings.TrimSpace(algorithm))
	if err != nil {
		return "", err
	}
	_, _ = hasher.Write(body)
	return strings.TrimSpace(algorithm) + ":" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyDescriptorBytes checks a complete descriptor payload and its response
// media type. Empty and application/octet-stream response types are accepted
// for blobs because registries commonly omit the descriptor media type there.
func VerifyDescriptorBytes(descriptor Descriptor, body []byte, responseMediaType string, allowGenericMediaType bool) error {
	if err := ValidateDigest(descriptor.Digest); err != nil {
		return err
	}
	if err := VerifyMediaType(descriptor.MediaType, responseMediaType, allowGenericMediaType, descriptor.Digest); err != nil {
		return err
	}
	if descriptor.Size < 0 {
		return &IntegrityError{Kind: IntegritySizeMismatch, Subject: descriptor.Digest, Expected: "non-negative size", Actual: fmt.Sprintf("%d", descriptor.Size)}
	}
	if int64(len(body)) != descriptor.Size {
		return &IntegrityError{Kind: IntegritySizeMismatch, Subject: descriptor.Digest, Expected: fmt.Sprintf("%d", descriptor.Size), Actual: fmt.Sprintf("%d", len(body))}
	}
	actual, err := DigestBytes(digestAlgorithm(descriptor.Digest), body)
	if err != nil {
		return err
	}
	if actual != descriptor.Digest {
		return &IntegrityError{Kind: IntegrityDigestMismatch, Subject: descriptor.Digest, Expected: descriptor.Digest, Actual: actual}
	}
	return nil
}

func VerifyMediaType(expected, actual string, allowGeneric bool, subject string) error {
	expected = MediaTypeBase(expected)
	actual = MediaTypeBase(actual)
	if expected == "" {
		return &IntegrityError{Kind: IntegrityMediaTypeMismatch, Subject: subject, Expected: "non-empty descriptor media type", Actual: actual}
	}
	if allowGeneric && (actual == "" || actual == "application/octet-stream") {
		return nil
	}
	if actual != expected {
		return &IntegrityError{Kind: IntegrityMediaTypeMismatch, Subject: subject, Expected: expected, Actual: actual}
	}
	return nil
}

func ValidateDocument(document Document) error {
	switch document.Kind {
	case DocumentKindManifest:
		return ValidateImageManifest(document.Manifest)
	case DocumentKindIndex:
		return ValidateImageIndex(document.Index)
	default:
		return &IntegrityError{Kind: IntegrityInvalidDocument, Subject: "manifest", Expected: "image manifest or image index", Actual: string(document.Kind)}
	}
}

func ValidateImageManifest(value ImageManifest) error {
	if value.SchemaVersion != 2 {
		return &IntegrityError{Kind: IntegrityInvalidDocument, Subject: "image manifest", Expected: "schemaVersion 2", Actual: fmt.Sprintf("schemaVersion %d", value.SchemaVersion)}
	}
	if !IsManifestMediaType(value.MediaType) {
		return &IntegrityError{Kind: IntegrityMediaTypeMismatch, Subject: "image manifest", Expected: "supported image manifest media type", Actual: MediaTypeBase(value.MediaType)}
	}
	if err := validateDescriptor(value.Config, IsConfigMediaType, "config"); err != nil {
		return err
	}
	for index, descriptor := range value.Layers {
		if err := validateDescriptor(descriptor, IsLayerMediaType, fmt.Sprintf("layer[%d]", index)); err != nil {
			return err
		}
	}
	return nil
}

func ValidateImageIndex(value ImageIndex) error {
	if value.SchemaVersion != 2 {
		return &IntegrityError{Kind: IntegrityInvalidDocument, Subject: "image index", Expected: "schemaVersion 2", Actual: fmt.Sprintf("schemaVersion %d", value.SchemaVersion)}
	}
	if !IsIndexMediaType(value.MediaType) {
		return &IntegrityError{Kind: IntegrityMediaTypeMismatch, Subject: "image index", Expected: "supported image index media type", Actual: MediaTypeBase(value.MediaType)}
	}
	if len(value.Manifests) == 0 {
		return &IntegrityError{Kind: IntegrityInvalidDocument, Subject: "image index", Expected: "at least one manifest descriptor", Actual: "none"}
	}
	for index, descriptor := range value.Manifests {
		if err := validateDescriptor(descriptor, IsManifestMediaType, fmt.Sprintf("manifest[%d]", index)); err != nil {
			return err
		}
		if err := ValidatePlatform(descriptor.Platform, false); err != nil {
			return &IntegrityError{Kind: IntegrityInvalidDocument, Subject: fmt.Sprintf("manifest[%d] platform", index), Expected: "valid OCI platform fields", Actual: "invalid platform", Cause: err}
		}
	}
	return nil
}

func validateDescriptor(descriptor Descriptor, supportedMediaType func(string) bool, subject string) error {
	if err := ValidateDigest(descriptor.Digest); err != nil {
		return fmt.Errorf("%s digest: %w", subject, err)
	}
	if descriptor.Size < 0 {
		return &IntegrityError{Kind: IntegritySizeMismatch, Subject: subject, Expected: "non-negative size", Actual: fmt.Sprintf("%d", descriptor.Size)}
	}
	if !supportedMediaType(descriptor.MediaType) {
		return &IntegrityError{Kind: IntegrityMediaTypeMismatch, Subject: subject, Expected: "supported OCI media type", Actual: MediaTypeBase(descriptor.MediaType)}
	}
	return nil
}

// MediaTypeBase removes optional HTTP media-type parameters.
func MediaTypeBase(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	return strings.ToLower(parsed)
}

type VerifyingReader struct {
	reader   io.Reader
	hasher   hash.Hash
	digest   string
	size     int64
	read     int64
	verified bool
	err      error
}

func NewVerifyingReader(reader io.Reader, descriptor Descriptor) (*VerifyingReader, error) {
	if reader == nil {
		return nil, fmt.Errorf("descriptor reader is required")
	}
	if err := ValidateDigest(descriptor.Digest); err != nil {
		return nil, err
	}
	hasher, err := newDigestHash(digestAlgorithm(descriptor.Digest))
	if err != nil {
		return nil, err
	}
	return &VerifyingReader{reader: reader, hasher: hasher, digest: descriptor.Digest, size: descriptor.Size}, nil
}

func (r *VerifyingReader) Read(buffer []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	count, err := r.reader.Read(buffer)
	if count > 0 {
		r.read += int64(count)
		_, _ = r.hasher.Write(buffer[:count])
		if r.size >= 0 && r.read > r.size {
			r.err = &IntegrityError{Kind: IntegritySizeMismatch, Subject: r.digest, Expected: fmt.Sprintf("%d", r.size), Actual: fmt.Sprintf("at least %d", r.read)}
			return count, r.err
		}
	}
	if err == io.EOF {
		r.err = r.verify()
		if r.err != nil {
			return count, r.err
		}
	}
	return count, err
}

func (r *VerifyingReader) Verify() error {
	if r.err != nil {
		return r.err
	}
	if !r.verified {
		return fmt.Errorf("descriptor %s was not read to completion", r.digest)
	}
	return nil
}

func (r *VerifyingReader) BytesRead() int64 {
	return r.read
}

func (r *VerifyingReader) verify() error {
	r.verified = true
	if r.size < 0 || r.read != r.size {
		return &IntegrityError{Kind: IntegritySizeMismatch, Subject: r.digest, Expected: fmt.Sprintf("%d", r.size), Actual: fmt.Sprintf("%d", r.read)}
	}
	actual := digestAlgorithm(r.digest) + ":" + hex.EncodeToString(r.hasher.Sum(nil))
	if actual != r.digest {
		return &IntegrityError{Kind: IntegrityDigestMismatch, Subject: r.digest, Expected: r.digest, Actual: actual}
	}
	return nil
}

func newDigestHash(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, &IntegrityError{Kind: IntegrityUnsupportedDigestAlgorithm, Subject: algorithm, Expected: "sha256 or sha512", Actual: algorithm}
	}
}

func digestAlgorithm(value string) string {
	algorithm, _, _ := strings.Cut(strings.TrimSpace(value), ":")
	return algorithm
}

func defaultIntegritySubject(value string) string {
	if strings.TrimSpace(value) == "" {
		return "descriptor"
	}
	return strings.TrimSpace(value)
}

func safeIntegrityField(value string) string {
	const maxRunes = 256
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > maxRunes {
		runes = append(runes[:maxRunes], '…')
	}
	return strconv.QuoteToASCII(string(runes))
}
