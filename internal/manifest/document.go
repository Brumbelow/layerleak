package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
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

	// Non-distributable (foreign) layers are referenced by URL instead of being
	// served by the registry. They are syntactically valid layer descriptors
	// that Layerleak does not download.
	MediaTypeOCIImageLayerNonDistributable     = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	MediaTypeOCIImageLayerNonDistributableGzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	MediaTypeOCIImageLayerNonDistributableZstd = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"

	// Common non-image index entries that are skipped rather than scanned.
	MediaTypeOCIEmptyJSON = "application/vnd.oci.empty.v1+json"
	MediaTypeInTotoJSON   = "application/vnd.in-toto+json"
)

// DefaultPlatformOS is the operating system whose manifests are selected from
// an image index when no platform selector is given.
const DefaultPlatformOS = "linux"

type Platform struct {
	OS           string `json:"os,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Variant      string `json:"variant,omitempty"`
}

type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Platform     Platform          `json:"platform,omitempty"`
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
	Healthcheck  Healthcheck            `json:"Healthcheck,omitempty"`
}

type Healthcheck struct {
	Test []string `json:"Test,omitempty"`
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

var platformComponentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]*$`)

const MaxPlatformComponentBytes = 128

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

// ParsePlatformSelector parses an os, os/arch or os/arch/variant selector.
// Omitted components act as wildcards when the selector is matched.
func ParsePlatformSelector(raw string) (Platform, error) {
	if raw == "" {
		return Platform{}, fmt.Errorf("platform selector is required")
	}
	if raw != strings.TrimSpace(raw) {
		return Platform{}, fmt.Errorf("platform selector must not include surrounding whitespace")
	}

	parts := strings.Split(raw, "/")
	if len(parts) > 3 {
		return Platform{}, fmt.Errorf("platform selector must be os, os/arch or os/arch/variant")
	}
	for _, part := range parts {
		if part == "" {
			return Platform{}, fmt.Errorf("platform selector components must not be empty")
		}
	}

	platform := Platform{OS: parts[0]}
	if len(parts) > 1 {
		platform.Architecture = parts[1]
	}
	if len(parts) > 2 {
		platform.Variant = parts[2]
	}

	if err := ValidatePlatform(platform, true); err != nil {
		return Platform{}, err
	}

	return platform, nil
}

// ValidatePlatform checks the syntax of every platform component. A selector
// must name an operating system and may only carry a variant alongside an
// architecture; descriptor platforms may leave every component empty.
func ValidatePlatform(platform Platform, selector bool) error {
	if selector && platform.OS == "" {
		return fmt.Errorf("platform selector must include an operating system")
	}
	if selector && platform.Variant != "" && platform.Architecture == "" {
		return fmt.Errorf("platform selector variant requires an architecture")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "os", value: platform.OS},
		{name: "architecture", value: platform.Architecture},
		{name: "variant", value: platform.Variant},
	} {
		name, value := field.name, field.value
		if value == "" {
			continue
		}
		if len(value) > MaxPlatformComponentBytes {
			return fmt.Errorf("platform %s exceeds %d bytes", name, MaxPlatformComponentBytes)
		}
		if value != strings.TrimSpace(value) || !platformComponentPattern.MatchString(value) {
			return fmt.Errorf("platform %s contains invalid characters", name)
		}
	}
	return nil
}

// SkipReason classifies an index entry that was not selected for scanning.
// The values double as diagnostic codes.
type SkipReason string

const (
	// SkipReasonUnsupportedManifest marks entries that are not scannable image
	// manifests: attestation manifests, nested indexes, artifact descriptors and
	// other non-image media types.
	SkipReasonUnsupportedManifest SkipReason = "manifest_skipped"
	// SkipReasonPlatform marks image manifests left out by the default
	// linux-only platform policy.
	SkipReasonPlatform SkipReason = "platform_skipped"
)

// SkippedDescriptor records why an index entry was not selected.
type SkippedDescriptor struct {
	Descriptor Descriptor
	Reason     SkipReason
	Detail     string
}

// Selection is the outcome of applying the platform policy to an image index.
type Selection struct {
	Selected []Descriptor
	Skipped  []SkippedDescriptor
}

// SelectManifests applies the platform policy to an image index.
//
// Without a selector every scannable image manifest whose platform OS is
// linux (or unspecified) is selected; non-image entries and manifests for
// other operating systems are reported in Skipped. With a selector only the
// matching image manifests are selected; entries that do not match the
// selector are left out silently and non-image entries that would otherwise
// match are reported.
func SelectManifests(index ImageIndex, selector string) (Selection, error) {
	explicit := strings.TrimSpace(selector) != ""
	var want Platform
	if explicit {
		parsed, err := ParsePlatformSelector(selector)
		if err != nil {
			return Selection{}, err
		}
		want = parsed
	}

	selection := Selection{
		Selected: make([]Descriptor, 0, len(index.Manifests)),
		Skipped:  make([]SkippedDescriptor, 0),
	}
	skip := func(descriptor Descriptor, reason SkipReason, detail string) {
		selection.Skipped = append(selection.Skipped, SkippedDescriptor{Descriptor: descriptor, Reason: reason, Detail: detail})
	}
	scannable := 0
	for _, candidate := range index.Manifests {
		if detail, ok := unsupportedIndexEntryDetail(candidate); ok {
			if !explicit || candidate.Platform.Matches(want) {
				skip(candidate, SkipReasonUnsupportedManifest, detail)
			}
			continue
		}
		scannable++
		if explicit {
			if candidate.Platform.Matches(want) {
				selection.Selected = append(selection.Selected, candidate)
			}
			continue
		}
		if isDefaultPlatform(candidate.Platform) {
			selection.Selected = append(selection.Selected, candidate)
			continue
		}
		skip(candidate, SkipReasonPlatform, fmt.Sprintf("skipped platform %s: only %s manifests are selected without a platform selector", candidate.Platform.String(), DefaultPlatformOS))
	}

	if len(selection.Selected) == 0 {
		switch {
		case scannable == 0:
			return Selection{}, fmt.Errorf("image index does not contain supported image manifests")
		case explicit:
			return Selection{}, fmt.Errorf("platform %s not found in manifest index", want.String())
		default:
			return Selection{}, fmt.Errorf("image index does not contain %s image manifests; select another platform explicitly", DefaultPlatformOS)
		}
	}

	unique, err := uniqueDescriptors(selection.Selected)
	if err != nil {
		return Selection{}, err
	}
	selection.Selected = unique
	return selection, nil
}

// SelectDescriptors returns only the selected descriptors of SelectManifests.
func SelectDescriptors(index ImageIndex, selector string) ([]Descriptor, error) {
	selection, err := SelectManifests(index, selector)
	if err != nil {
		return nil, err
	}
	return selection.Selected, nil
}

func unsupportedIndexEntryDetail(descriptor Descriptor) (string, bool) {
	switch {
	case IsIndexMediaType(descriptor.MediaType):
		return "skipped index entry: nested image indexes are not scanned", true
	case !IsManifestMediaType(descriptor.MediaType):
		return fmt.Sprintf("skipped index entry: media type %q is not an image manifest", MediaTypeBase(descriptor.MediaType)), true
	case IsAttestationDescriptor(descriptor):
		return "skipped attestation manifest", true
	default:
		return "", false
	}
}

func isDefaultPlatform(platform Platform) bool {
	os := strings.ToLower(strings.TrimSpace(platform.OS))
	return os == "" || os == DefaultPlatformOS
}

func uniqueDescriptors(items []Descriptor) ([]Descriptor, error) {
	selected := make([]Descriptor, 0, len(items))
	seen := make(map[string]Descriptor, len(items))
	for _, item := range items {
		if previous, ok := seen[item.Digest]; ok {
			if previous.MediaType != item.MediaType || previous.Size != item.Size || previous.Platform != item.Platform {
				return nil, &IntegrityError{
					Kind:     IntegrityInvalidDocument,
					Subject:  item.Digest,
					Expected: "one consistent descriptor per digest",
					Actual:   "conflicting descriptors",
				}
			}
			continue
		}
		seen[item.Digest] = item
		selected = append(selected, item)
	}
	return selected, nil
}

// Matches reports whether the descriptor platform p satisfies selector. An
// empty selector architecture or variant acts as a wildcard, and variants are
// normalised the way containerd does so linux/arm64/v8 and linux/arm64 are
// interchangeable, linux/arm means linux/arm/v7, and amd64 microarchitecture
// levels are ignored.
func (p Platform) Matches(selector Platform) bool {
	descriptor := normalizePlatform(p)
	want := normalizePlatform(selector)
	if want.OS == "" || descriptor.OS != want.OS {
		return false
	}
	if want.Architecture == "" {
		return true
	}
	if descriptor.Architecture != want.Architecture {
		return false
	}
	if strings.TrimSpace(selector.Variant) == "" {
		return true
	}
	return descriptor.Variant == want.Variant
}

func normalizePlatform(platform Platform) Platform {
	normalized := Platform{
		OS:           strings.ToLower(strings.TrimSpace(platform.OS)),
		Architecture: strings.ToLower(strings.TrimSpace(platform.Architecture)),
		Variant:      strings.ToLower(strings.TrimSpace(platform.Variant)),
	}
	switch normalized.Architecture {
	case "amd64", "386":
		normalized.Variant = ""
	case "arm64":
		if normalized.Variant == "v8" || normalized.Variant == "8" {
			normalized.Variant = ""
		}
	case "arm":
		switch normalized.Variant {
		case "", "7":
			normalized.Variant = "v7"
		case "5", "6", "8":
			normalized.Variant = "v" + normalized.Variant
		}
	}
	return normalized
}

func IsScannableManifestDescriptor(descriptor Descriptor) bool {
	if !IsManifestMediaType(descriptor.MediaType) {
		return false
	}
	if IsAttestationDescriptor(descriptor) {
		return false
	}
	return true
}

func IsAttestationDescriptor(descriptor Descriptor) bool {
	if !IsManifestMediaType(descriptor.MediaType) {
		return false
	}

	referenceType := strings.ToLower(strings.TrimSpace(descriptor.Annotations["vnd.docker.reference.type"]))
	if referenceType == "attestation-manifest" {
		return true
	}
	if strings.TrimSpace(descriptor.ArtifactType) != "" {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(descriptor.Platform.OS), "unknown") &&
		strings.EqualFold(strings.TrimSpace(descriptor.Platform.Architecture), "unknown")
}

func (p Platform) String() string {
	os := strings.ToLower(strings.TrimSpace(p.OS))
	architecture := strings.ToLower(strings.TrimSpace(p.Architecture))
	variant := strings.ToLower(strings.TrimSpace(p.Variant))
	if os == "" && architecture == "" {
		return ""
	}
	if architecture == "" {
		return os
	}
	if variant == "" {
		return os + "/" + architecture
	}
	return os + "/" + architecture + "/" + variant
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

// IsForeignLayerMediaType reports Docker foreign and OCI non-distributable
// layer media types. They are valid descriptors but cannot be scanned.
func IsForeignLayerMediaType(mediaType string) bool {
	switch normalizeMediaType(mediaType) {
	case MediaTypeDockerSchema2ForeignLayer, MediaTypeDockerSchema2ForeignLayerGzip,
		MediaTypeOCIImageLayerNonDistributable, MediaTypeOCIImageLayerNonDistributableGzip, MediaTypeOCIImageLayerNonDistributableZstd:
		return true
	default:
		return false
	}
}

// IsLayerDescriptorMediaType reports every media type that may appear in an
// image manifest's layers array, scannable or not.
func IsLayerDescriptorMediaType(mediaType string) bool {
	return IsLayerMediaType(mediaType) || IsForeignLayerMediaType(mediaType)
}

func LayerCompression(mediaType string) string {
	switch normalizeMediaType(mediaType) {
	case MediaTypeOCIImageLayerGzip, MediaTypeDockerSchema2LayerGzip, MediaTypeDockerSchema2ForeignLayerGzip, MediaTypeOCIImageLayerNonDistributableGzip:
		return "gzip"
	case MediaTypeOCIImageLayerZstd, MediaTypeOCIImageLayerNonDistributableZstd:
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
	appendSliceField("config.healthcheck.test", cfg.Config.Healthcheck.Test)
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
	appendSliceField("container_config.healthcheck.test", cfg.ContainerConfig.Healthcheck.Test)
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
