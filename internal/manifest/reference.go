package manifest

import (
	"fmt"
	"strings"
)

const DockerHubRegistry = "docker.io"

type Reference struct {
	Original   string
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

func ParseReference(raw string) (Reference, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Reference{}, fmt.Errorf("image reference is required")
	}

	if strings.Contains(value, "://") {
		return Reference{}, fmt.Errorf("image reference must not include a scheme")
	}

	namePart := value
	digest := ""
	if at := strings.LastIndex(value, "@"); at >= 0 {
		namePart = value[:at]
		digest = value[at+1:]
		if digest == "" {
			return Reference{}, fmt.Errorf("digest is required when @ is present")
		}
		if !strings.Contains(digest, ":") {
			return Reference{}, fmt.Errorf("digest must include an algorithm prefix")
		}
	}

	tag := ""
	pathPart := namePart
	if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
		tag = namePart[colon+1:]
		pathPart = namePart[:colon]
		if tag == "" {
			return Reference{}, fmt.Errorf("tag is required when : is present")
		}
	}

	segments := strings.Split(pathPart, "/")
	registry := DockerHubRegistry
	repositorySegments := segments

	if isRegistrySegment(segments[0]) {
		registry = normalizeRegistry(segments[0])
		if !isDockerHubRegistry(registry) {
			return Reference{}, fmt.Errorf("only public Docker Hub references are supported: %s", segments[0])
		}
		repositorySegments = segments[1:]
	}

	if len(repositorySegments) == 0 {
		return Reference{}, fmt.Errorf("repository is required")
	}

	if len(repositorySegments) == 1 {
		repositorySegments = []string{"library", repositorySegments[0]}
	}

	repository := strings.Join(repositorySegments, "/")
	if repository == "" || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") {
		return Reference{}, fmt.Errorf("repository is invalid")
	}

	if digest == "" && tag == "" {
		tag = "latest"
	}

	return Reference{
		Original:   value,
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
	}, nil
}

func (r Reference) Identifier() string {
	if r.Digest != "" {
		return r.Digest
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

func isRegistrySegment(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || value == "localhost"
}

func normalizeRegistry(value string) string {
	switch strings.ToLower(value) {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return DockerHubRegistry
	default:
		return strings.ToLower(value)
	}
}

func isDockerHubRegistry(value string) bool {
	return value == DockerHubRegistry
}
