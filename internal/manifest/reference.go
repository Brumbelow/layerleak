package manifest

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	distributionreference "github.com/distribution/reference"
	ocidigest "github.com/opencontainers/go-digest"
)

const DockerHubRegistry = "docker.io"

type Reference struct {
	Original    string
	Registry    string
	Repository  string
	Tag         string
	Digest      string
	TagExplicit bool
}

func ParseReference(raw string) (Reference, error) {
	value := raw
	if value == "" {
		return Reference{}, fmt.Errorf("image reference is required")
	}
	if value != strings.TrimSpace(value) {
		return Reference{}, fmt.Errorf("image reference must not include surrounding whitespace")
	}

	if strings.Contains(value, "://") {
		return Reference{}, fmt.Errorf("image reference must not include a scheme")
	}
	if strings.ContainsAny(value, `?#\\`) {
		return Reference{}, fmt.Errorf("image reference contains invalid characters")
	}
	if strings.Count(value, "@") > 1 {
		return Reference{}, fmt.Errorf("image reference must contain at most one digest separator")
	}

	named, err := distributionreference.ParseNormalizedNamed(value)
	if err != nil {
		return Reference{}, fmt.Errorf("parse image reference: %w", err)
	}

	registry := normalizeRegistry(distributionreference.Domain(named))
	if err := validateRegistry(registry); err != nil {
		return Reference{}, err
	}
	repository := distributionreference.Path(named)
	if repository == "" {
		return Reference{}, fmt.Errorf("repository is required")
	}

	tag := ""
	if tagged, ok := named.(distributionreference.Tagged); ok {
		tag = tagged.Tag()
	}
	digest := ""
	if digested, ok := named.(distributionreference.Digested); ok {
		digest = digested.Digest().String()
		if err := ValidateDigest(digest); err != nil {
			return Reference{}, err
		}
	}

	return Reference{
		Original:    value,
		Registry:    registry,
		Repository:  repository,
		Tag:         tag,
		Digest:      digest,
		TagExplicit: tag != "",
	}, nil
}

// ValidateDigest verifies the OCI digest syntax and the encoded length for the
// digest algorithms layerleak can calculate locally.
func ValidateDigest(value string) error {
	trimmed := strings.TrimSpace(value)
	if value != trimmed {
		return &IntegrityError{Kind: IntegrityInvalidDigest, Subject: value, Expected: "OCI digest without surrounding whitespace", Actual: value}
	}
	parsed, err := ocidigest.Parse(value)
	if err != nil {
		return &IntegrityError{Kind: IntegrityInvalidDigest, Subject: value, Expected: "valid OCI digest", Actual: value, Cause: err}
	}
	switch parsed.Algorithm() {
	case ocidigest.SHA256, ocidigest.SHA512:
		return nil
	default:
		return &IntegrityError{
			Kind:     IntegrityUnsupportedDigestAlgorithm,
			Subject:  parsed.String(),
			Expected: "sha256 or sha512",
			Actual:   parsed.Algorithm().String(),
		}
	}
}

func (r Reference) Identifier() string {
	if r.Digest != "" {
		return r.Digest
	}
	if r.Tag == "" {
		return "latest"
	}

	return r.Tag
}

func (r Reference) CanonicalString(digest string) string {
	value := r.Registry + "/" + r.Repository
	if strings.TrimSpace(digest) != "" {
		return value + "@" + strings.TrimSpace(digest)
	}
	if r.Digest != "" {
		return value + "@" + r.Digest
	}
	if r.Tag != "" {
		return value + ":" + r.Tag
	}
	return value
}

func (r Reference) RepositoryString() string {
	return r.Registry + "/" + r.Repository
}

func (r Reference) IsRepositoryOnly() bool {
	return r.Digest == "" && !r.TagExplicit && r.Tag == ""
}

func (r Reference) WithTag(tag string) Reference {
	return Reference{
		Original:    r.Registry + "/" + r.Repository + ":" + strings.TrimSpace(tag),
		Registry:    r.Registry,
		Repository:  r.Repository,
		Tag:         strings.TrimSpace(tag),
		TagExplicit: true,
	}
}

func (r Reference) WithDigest(digest string) Reference {
	return Reference{
		Original:   r.Registry + "/" + r.Repository + "@" + strings.TrimSpace(digest),
		Registry:   r.Registry,
		Repository: r.Repository,
		Digest:     strings.TrimSpace(digest),
	}
}

func (r Reference) RepositoryScope() string {
	return "repository:" + r.Repository + ":pull"
}

func (r Reference) String() string {
	value := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		value += ":" + r.Tag
	}
	if r.Digest != "" {
		value += "@" + r.Digest
	}

	return value
}

func normalizeRegistry(value string) string {
	switch strings.ToLower(value) {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return DockerHubRegistry
	default:
		return strings.ToLower(value)
	}
}

func validateRegistry(value string) error {
	host := value
	if strings.HasPrefix(value, "[") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return fmt.Errorf("registry is invalid: %w", err)
		}
		if err := validatePort(port); err != nil {
			return err
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("registry host is invalid")
		}
		return nil
	}

	if colon := strings.LastIndexByte(value, ':'); colon >= 0 {
		if strings.Count(value, ":") != 1 {
			return fmt.Errorf("IPv6 registry hosts must use brackets")
		}
		host = value[:colon]
		if err := validatePort(value[colon+1:]); err != nil {
			return err
		}
	}
	if host == "" {
		return fmt.Errorf("registry host is invalid")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("registry host is invalid")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("registry host is invalid")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("registry host is invalid")
			}
		}
	}
	return nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("registry port is invalid")
	}
	return nil
}
