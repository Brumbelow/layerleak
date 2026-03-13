package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	MediaTypeOCIImageManifest              = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIImageIndex                 = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerSchema2Manifest         = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerSchema2ManifestList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIImageConfig                = "application/vnd.oci.image.config.v1+json"
	MediaTypeDockerContainerConfig         = "application/vnd.docker.container.image.v1+json"
	MediaTypeOCIImageLayer                 = "application/vnd.oci.image.layer.v1.tar"
	MediaTypeOCIImageLayerGzip             = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaTypeOCIImageLayerZstd             = "application/vnd.oci.image.layer.v1.tar+zstd"
	MediaTypeDockerSchema2Layer            = "application/vnd.docker.image.rootfs.diff.tar"
	MediaTypeDockerSchema2LayerGzip        = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	MediaTypeDockerSchema2ForeignLayer     = "application/vnd.docker.image.rootfs.foreign.diff.tar"
	MediaTypeDockerSchema2ForeignLayerGzip = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
)

type Platform struct {
	OS           string `json:"os,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Variant      string `json:"variant,omitempty"`
}

type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    Platform          `json:"platform,omitempty"`
}

type ImageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type ImageIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

type HistoryEntry struct {
	Author     string `json:"author,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

type ImageConfigPayload struct {
	Hostname     string                 `json:"Hostname,omitempty"`
	Domainname   string                 `json:"Domainname,omitempty"`
	User         string                 `json:"User,omitempty"`
	Env          []string               `json:"Env,omitempty"`
	Cmd          []string               `json:"Cmd,omitempty"`
	Entrypoint   []string               `json:"Entrypoint,omitempty"`
	Shell        []string               `json:"Shell,omitempty"`
	WorkingDir   string                 `json:"WorkingDir,omitempty"`
	Labels       map[string]string      `json:"Labels,omitempty"`
	OnBuild      []string               `json:"OnBuild,omitempty"`
	ExposedPorts map[string]interface{} `json:"ExposedPorts,omitempty"`
	Volumes      map[string]interface{} `json:"Volumes,omitempty"`
}

type ImageConfig struct {
	Architecture    string             `json:"architecture,omitempty"`
	OS              string             `json:"os,omitempty"`
	Variant         string             `json:"variant,omitempty"`
	Author          string             `json:"author,omitempty"`
	Config          ImageConfigPayload `json:"config,omitempty"`
	Container       string             `json:"container,omitempty"`
	ContainerConfig ImageConfigPayload `json:"container_config,omitempty"`
	History         []HistoryEntry     `json:"history,omitempty"`
}

type ConfigField struct {
	Key   string
	Value string
}

type DocumentKind string

const (
	DocumentKindManifest DocumentKind = "manifest"
	DocumentKindIndex    DocumentKind = "index"
)

type Document struct {
	Kind     DocumentKind
	Manifest ImageManifest
	Index    ImageIndex
}

func ParseDocument(mediaType string, body []byte) (Document, error) {
	type probe struct {
		Manifests json.RawMessage `json:"manifests"`
		Config    json.RawMessage `json:"config"`
		Layers    json.RawMessage `json:"layers"`
	}

	var p probe
	if err := json.Unmarshal(body, &p); err != nil {
		return Document{}, fmt.Errorf("decode manifest document: %w", err)
	}

	normalizedMediaType := normalizeMediaType(mediaType)
	switch {
	case len(p.Manifests) > 0 || normalizedMediaType == MediaTypeOCIImageIndex || normalizedMediaType == MediaTypeDockerSchema2ManifestList:
		var index ImageIndex
		if err := json.Unmarshal(body, &index); err != nil {
			return Document{}, fmt.Errorf("decode image index: %w", err)
		}
		if index.MediaType == "" {
			index.MediaType = normalizedMediaType
		}
		return Document{
			Kind:  DocumentKindIndex,
			Index: index,
		}, nil
	case len(p.Config) > 0 || len(p.Layers) > 0 || normalizedMediaType == MediaTypeOCIImageManifest || normalizedMediaType == MediaTypeDockerSchema2Manifest:
		var imageManifest ImageManifest
		if err := json.Unmarshal(body, &imageManifest); err != nil {
			return Document{}, fmt.Errorf("decode image manifest: %w", err)
		}
		if imageManifest.MediaType == "" {
			imageManifest.MediaType = normalizedMediaType
		}
		return Document{
			Kind:     DocumentKindManifest,
			Manifest: imageManifest,
		}, nil
	default:
		return Document{}, fmt.Errorf("unsupported manifest media type: %s", mediaType)
	}
}

func ParseImageConfig(body []byte) (ImageConfig, error) {
	var cfg ImageConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return ImageConfig{}, fmt.Errorf("decode image config: %w", err)
	}

	return cfg, nil
}

func ParsePlatformSelector(raw string) (Platform, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Platform{}, fmt.Errorf("platform selector is required")
	}

	parts := strings.Split(value, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return Platform{}, fmt.Errorf("platform selector must be os/arch or os/arch/variant")
	}

	platform := Platform{
		OS:           strings.TrimSpace(parts[0]),
		Architecture: strings.TrimSpace(parts[1]),
	}
	if len(parts) == 3 {
		platform.Variant = strings.TrimSpace(parts[2])
	}

	if platform.OS == "" || platform.Architecture == "" {
		return Platform{}, fmt.Errorf("platform selector must include os and architecture")
	}

	return platform, nil
}

func SelectDescriptors(index ImageIndex, selector string) ([]Descriptor, error) {
	if strings.TrimSpace(selector) == "" {
		selected := slices.Clone(index.Manifests)
		selected = slices.DeleteFunc(selected, func(item Descriptor) bool {
			return !IsManifestMediaType(item.MediaType)
		})
		if len(selected) == 0 {
			return nil, fmt.Errorf("image index does not contain supported image manifests")
		}
		return selected, nil
	}

	platform, err := ParsePlatformSelector(selector)
	if err != nil {
		return nil, err
	}

	matches := make([]Descriptor, 0)
	for _, candidate := range index.Manifests {
		if !IsManifestMediaType(candidate.MediaType) {
			continue
		}
		if candidate.Platform.Matches(platform) {
			matches = append(matches, candidate)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("platform %s not found in manifest index", platform.String())
	}

	return matches, nil
}

func (p Platform) Matches(other Platform) bool {
	if !equalFoldOrEmpty(p.OS, other.OS) {
		return false
	}
	if !equalFoldOrEmpty(p.Architecture, other.Architecture) {
		return false
	}
	if strings.TrimSpace(other.Variant) == "" {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(p.Variant), strings.TrimSpace(other.Variant))
}

func (p Platform) String() string {
	if p.OS == "" && p.Architecture == "" {
		return ""
	}
	if p.Variant == "" {
		return strings.ToLower(strings.TrimSpace(p.OS)) + "/" + strings.ToLower(strings.TrimSpace(p.Architecture))
	}
	return strings.ToLower(strings.TrimSpace(p.OS)) + "/" + strings.ToLower(strings.TrimSpace(p.Architecture)) + "/" + strings.ToLower(strings.TrimSpace(p.Variant))
}

func IsIndexMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageIndex, MediaTypeDockerSchema2ManifestList:
		return true
	default:
		return false
	}
}

func IsManifestMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageManifest, MediaTypeDockerSchema2Manifest:
		return true
	default:
		return false
	}
}

func IsConfigMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageConfig, MediaTypeDockerContainerConfig:
		return true
	default:
		return false
	}
}

func IsLayerMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageLayer, MediaTypeOCIImageLayerGzip, MediaTypeOCIImageLayerZstd, MediaTypeDockerSchema2Layer, MediaTypeDockerSchema2LayerGzip:
		return true
	default:
		return false
	}
}

func IsForeignLayerMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeDockerSchema2ForeignLayer, MediaTypeDockerSchema2ForeignLayerGzip:
		return true
	default:
		return false
	}
}

func LayerCompression(mediaType string) string {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageLayerGzip, MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2ForeignLayerGzip:
		return "gzip"
	case MediaTypeOCIImageLayerZstd:
		return "zstd"
	default:
		return ""
	}
}

func ConfigFields(cfg ImageConfig) []ConfigField {
	fields := make([]ConfigField, 0)
	appendStringField := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		fields = append(fields, ConfigField{
			Key:   key,
			Value: value,
		})
	}
	appendSliceField := func(key string, values []string) {
		for index, value := range values {
			appendStringField(fmt.Sprintf("%s[%d]", key, index), value)
		}
	}
	appendMapKeys := func(key string, values map[string]interface{}) {
		keys := make([]string, 0, len(values))
		for value := range values {
			keys = append(keys, value)
		}
		slices.Sort(keys)
		for _, value := range keys {
			appendStringField(key, value)
		}
	}

	appendStringField("author", cfg.Author)
	appendStringField("container", cfg.Container)
	appendStringField("config.hostname", cfg.Config.Hostname)
	appendStringField("config.domainname", cfg.Config.Domainname)
	appendStringField("config.user", cfg.Config.User)
	appendStringField("config.working_dir", cfg.Config.WorkingDir)
	appendSliceField("config.cmd", cfg.Config.Cmd)
	appendSliceField("config.entrypoint", cfg.Config.Entrypoint)
	appendSliceField("config.shell", cfg.Config.Shell)
	appendSliceField("config.onbuild", cfg.Config.OnBuild)
	appendMapKeys("config.exposed_ports", cfg.Config.ExposedPorts)
	appendMapKeys("config.volumes", cfg.Config.Volumes)
	appendStringField("container_config.hostname", cfg.ContainerConfig.Hostname)
	appendStringField("container_config.domainname", cfg.ContainerConfig.Domainname)
	appendStringField("container_config.user", cfg.ContainerConfig.User)
	appendStringField("container_config.working_dir", cfg.ContainerConfig.WorkingDir)
	appendSliceField("container_config.cmd", cfg.ContainerConfig.Cmd)
	appendSliceField("container_config.entrypoint", cfg.ContainerConfig.Entrypoint)
	appendSliceField("container_config.shell", cfg.ContainerConfig.Shell)
	appendSliceField("container_config.onbuild", cfg.ContainerConfig.OnBuild)
	appendMapKeys("container_config.exposed_ports", cfg.ContainerConfig.ExposedPorts)
	appendMapKeys("container_config.volumes", cfg.ContainerConfig.Volumes)

	return fields
}

func normalizeMediaType(mediaType string) string {
	value := strings.TrimSpace(mediaType)
	if value == "" {
		return ""
	}
	if index := strings.Index(value, ";"); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func equalFoldOrEmpty(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	return strings.EqualFold(left, right)
}
