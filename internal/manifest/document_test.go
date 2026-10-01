package manifest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// FuzzImageConfig drives the image-config and manifest-document parsers with
// arbitrary bytes. Both consume registry responses that are hostile by
// assumption, so they must never panic, must return typed JSON errors for
// unparsable input, and whatever parses must validate with typed integrity
// errors only. Run it longer with
// `go test -run=^$ -fuzz=FuzzImageConfig -fuzztime=60s ./internal/manifest`.
func FuzzImageConfig(f *testing.F) {
	for _, seed := range []string{
		`{"architecture":"amd64","os":"linux","config":{"Env":["A=b"],"Labels":{"k":"v"},"ExposedPorts":{"80/tcp":{}}},"history":[{"created_by":"RUN x"}]}`,
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":1},"layers":[]}`,
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.in-toto+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":1}]}`,
		`{"manifests":[{"platform":{"os":"linux\n"}}]}`,
		`{"config":{"Env":"not-a-list"}}`,
		`{}`, `[]`, `null`, `"string"`, `{"architecture":`, "\xff\xfe", "",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip("bounded by MaxConfigBytes/MaxManifestBytes in production")
		}
		config, err := ParseImageConfig(body)
		if err != nil {
			var syntaxErr *json.SyntaxError
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &syntaxErr) && !errors.As(err, &typeErr) {
				t.Fatalf("ParseImageConfig() returned an untyped error: %v", err)
			}
		} else {
			_ = ConfigFields(config)
			_ = ValidatePlatform(Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}, false)
		}

		for _, mediaType := range []string{MediaTypeOCIImageManifest, MediaTypeOCIImageIndex, MediaTypeDockerSchema2Manifest, ""} {
			document, err := ParseDocument(mediaType, body)
			if err != nil {
				continue
			}
			if err := ValidateDocument(document); err != nil {
				if !IsIntegrityError(err) {
					t.Fatalf("ValidateDocument() returned an untyped error: %v", err)
				}
				continue
			}
			if document.Kind == DocumentKindIndex {
				// Selection may legitimately find nothing; it must not panic and
				// must not report an integrity failure for a validated index
				// unless descriptors conflict.
				if _, err := SelectManifests(document.Index, ""); err != nil && IsIntegrityError(err) && !strings.Contains(err.Error(), "conflicting descriptors") {
					t.Fatalf("SelectManifests() error = %v", err)
				}
			}
		}
	})
}

func TestParseDocumentIndex(t *testing.T) {
	body := []byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "size": 123,
      "platform": {
        "os": "linux",
        "architecture": "amd64"
      }
    }
  ]
}`)

	document, err := ParseDocument(MediaTypeOCIImageIndex, body)
	if err != nil {
		t.Fatalf("ParseDocument() error = %v", err)
	}

	if document.Kind != DocumentKindIndex {
		t.Fatalf("document.Kind = %q", document.Kind)
	}

	if len(document.Index.Manifests) != 1 {
		t.Fatalf("len(document.Index.Manifests) = %d", len(document.Index.Manifests))
	}
}

func TestSelectDescriptors(t *testing.T) {
	index := ImageIndex{
		Manifests: []Descriptor{
			{
				MediaType: MediaTypeOCIImageManifest,
				Digest:    "sha256:amd64",
				Platform: Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			{
				MediaType: MediaTypeOCIImageManifest,
				Digest:    "sha256:arm64",
				Platform: Platform{
					OS:           "linux",
					Architecture: "arm64",
				},
			},
		},
	}

	selected, err := SelectDescriptors(index, "linux/arm64")
	if err != nil {
		t.Fatalf("SelectDescriptors() error = %v", err)
	}

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d", len(selected))
	}

	if selected[0].Digest != "sha256:arm64" {
		t.Fatalf("selected[0].Digest = %q", selected[0].Digest)
	}
}

func TestSelectDescriptorsSkipsAttestationManifests(t *testing.T) {
	index := ImageIndex{
		Manifests: []Descriptor{
			{
				MediaType: MediaTypeOCIImageManifest,
				Digest:    "sha256:amd64",
				Platform: Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			{
				MediaType:    MediaTypeOCIImageManifest,
				ArtifactType: "application/vnd.in-toto+json",
				Digest:       "sha256:attestation",
				Annotations: map[string]string{
					"vnd.docker.reference.type": "attestation-manifest",
				},
				Platform: Platform{
					OS:           "unknown",
					Architecture: "unknown",
				},
			},
		},
	}

	selected, err := SelectDescriptors(index, "")
	if err != nil {
		t.Fatalf("SelectDescriptors() error = %v", err)
	}

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d", len(selected))
	}
	if selected[0].Digest != "sha256:amd64" {
		t.Fatalf("selected[0].Digest = %q", selected[0].Digest)
	}
}

func TestSelectDescriptorsDeduplicatesEquivalentDigests(t *testing.T) {
	descriptor := Descriptor{
		MediaType: MediaTypeOCIImageManifest,
		Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Size:      123,
		Platform:  Platform{OS: "linux", Architecture: "amd64"},
	}
	selected, err := SelectDescriptors(ImageIndex{Manifests: []Descriptor{descriptor, descriptor}}, "")
	if err != nil {
		t.Fatalf("SelectDescriptors() error = %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d", len(selected))
	}

	conflicting := descriptor
	conflicting.Platform.Architecture = "arm64"
	if _, err := SelectDescriptors(ImageIndex{Manifests: []Descriptor{descriptor, conflicting}}, ""); err == nil || !strings.Contains(err.Error(), "conflicting descriptors") {
		t.Fatalf("SelectDescriptors(conflict) error = %v", err)
	}
}

func TestParsePlatformSelectorRejectsUnsafeComponents(t *testing.T) {
	for _, value := range []string{
		"linux/amd64\nforged",
		"linux/amd64\x1b[2J",
		" linux/amd64",
		"linux/AMD64",
		"linux/" + strings.Repeat("a", MaxPlatformComponentBytes+1),
	} {
		if _, err := ParsePlatformSelector(value); err == nil {
			t.Fatalf("ParsePlatformSelector(%q) error = nil", value)
		}
	}
}

func TestValidatePlatformBoundsEveryComponent(t *testing.T) {
	maximum := "a" + strings.Repeat("b", MaxPlatformComponentBytes-1)
	tooLong := maximum + "c"
	for _, test := range []struct {
		name     string
		platform Platform
	}{
		{name: "os", platform: Platform{OS: tooLong}},
		{name: "architecture", platform: Platform{Architecture: tooLong}},
		{name: "variant", platform: Platform{Variant: tooLong}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePlatform(test.platform, false); err == nil || !strings.Contains(err.Error(), "exceeds 128 bytes") {
				t.Fatalf("ValidatePlatform() error = %v", err)
			}
		})
	}

	if err := ValidatePlatform(Platform{OS: maximum, Architecture: maximum, Variant: maximum}, true); err != nil {
		t.Fatalf("ValidatePlatform(maximum) error = %v", err)
	}
}

func TestConfigFields(t *testing.T) {
	fields := ConfigFields(ImageConfig{
		Author: "builder",
		Config: ImageConfigPayload{
			User:       "root",
			WorkingDir: "/app",
			Cmd:        []string{"run", "server"},
			Healthcheck: Healthcheck{
				Test: []string{"CMD-SHELL", "curl -u admin:real-secret@example.invalid/health"},
			},
		},
		ContainerConfig: ImageConfigPayload{
			Healthcheck: Healthcheck{Test: []string{"CMD", "legacy-healthcheck-secret"}},
		},
	})

	if len(fields) == 0 {
		t.Fatal("len(fields) = 0")
	}
	want := map[string]string{
		"config.healthcheck.test[1]":           "curl -u admin:real-secret@example.invalid/health",
		"container_config.healthcheck.test[1]": "legacy-healthcheck-secret",
	}
	for _, field := range fields {
		if value, ok := want[field.Key]; ok && field.Value == value {
			delete(want, field.Key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("ConfigFields() missing healthcheck fields: %v", want)
	}
}

func TestParsePlatformSelectorAcceptsOSAndOSArchitecture(t *testing.T) {
	tests := []struct {
		raw  string
		want Platform
	}{
		{raw: "linux", want: Platform{OS: "linux"}},
		{raw: "linux/arm64", want: Platform{OS: "linux", Architecture: "arm64"}},
		{raw: "linux/arm64/v8", want: Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{raw: "windows/amd64", want: Platform{OS: "windows", Architecture: "amd64"}},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := ParsePlatformSelector(test.raw)
			if err != nil {
				t.Fatalf("ParsePlatformSelector(%q) error = %v", test.raw, err)
			}
			if got != test.want {
				t.Fatalf("ParsePlatformSelector(%q) = %#v, want %#v", test.raw, got, test.want)
			}
		})
	}

	for _, raw := range []string{"", "linux/", "/amd64", "linux//v8", "linux/amd64/", "linux/amd64/v8/extra"} {
		if _, err := ParsePlatformSelector(raw); err == nil {
			t.Fatalf("ParsePlatformSelector(%q) error = nil", raw)
		}
	}
}

func TestPlatformMatchesNormalizesVariantsLikeContainerd(t *testing.T) {
	tests := []struct {
		name       string
		descriptor Platform
		selector   Platform
		want       bool
	}{
		{name: "os only", descriptor: Platform{OS: "linux", Architecture: "s390x"}, selector: Platform{OS: "linux"}, want: true},
		{name: "os only rejects other os", descriptor: Platform{OS: "windows", Architecture: "amd64"}, selector: Platform{OS: "linux"}, want: false},
		{name: "arm64 v8 selector matches bare arm64", descriptor: Platform{OS: "linux", Architecture: "arm64"}, selector: Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, want: true},
		{name: "arm64 selector matches v8 descriptor", descriptor: Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, selector: Platform{OS: "linux", Architecture: "arm64"}, want: true},
		{name: "arm v7 selector matches bare arm", descriptor: Platform{OS: "linux", Architecture: "arm"}, selector: Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, want: true},
		{name: "arm v6 selector rejects bare arm", descriptor: Platform{OS: "linux", Architecture: "arm"}, selector: Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, want: false},
		{name: "arm selector without variant is a wildcard", descriptor: Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, selector: Platform{OS: "linux", Architecture: "arm"}, want: true},
		{name: "amd64 variant is ignored", descriptor: Platform{OS: "linux", Architecture: "amd64"}, selector: Platform{OS: "linux", Architecture: "amd64", Variant: "v3"}, want: true},
		{name: "architecture mismatch", descriptor: Platform{OS: "linux", Architecture: "amd64"}, selector: Platform{OS: "linux", Architecture: "arm64"}, want: false},
		{name: "descriptor without os never matches", descriptor: Platform{Architecture: "amd64"}, selector: Platform{OS: "linux", Architecture: "amd64"}, want: false},
		{name: "case insensitive", descriptor: Platform{OS: "Linux", Architecture: "ARM64", Variant: "V8"}, selector: Platform{OS: "linux", Architecture: "arm64"}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.descriptor.Matches(test.selector); got != test.want {
				t.Fatalf("%#v.Matches(%#v) = %t, want %t", test.descriptor, test.selector, got, test.want)
			}
		})
	}
}

func TestPlatformStringOmitsEmptyComponents(t *testing.T) {
	for _, test := range []struct {
		platform Platform
		want     string
	}{
		{platform: Platform{}, want: ""},
		{platform: Platform{OS: "linux"}, want: "linux"},
		{platform: Platform{OS: "linux", Architecture: "arm64"}, want: "linux/arm64"},
		{platform: Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, want: "linux/arm/v7"},
	} {
		if got := test.platform.String(); got != test.want {
			t.Fatalf("%#v.String() = %q, want %q", test.platform, got, test.want)
		}
	}
}

func policyTestIndex() ImageIndex {
	return ImageIndex{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIImageIndex,
		Manifests: []Descriptor{
			{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("1", 64), Size: 1, Platform: Platform{OS: "linux", Architecture: "amd64"}},
			{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("2", 64), Size: 1, Platform: Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
			{MediaType: MediaTypeDockerSchema2Manifest, Digest: "sha256:" + strings.Repeat("3", 64), Size: 1, Platform: Platform{OS: "windows", Architecture: "amd64"}},
			{
				MediaType:    MediaTypeOCIImageManifest,
				ArtifactType: MediaTypeInTotoJSON,
				Digest:       "sha256:" + strings.Repeat("4", 64),
				Size:         1,
				Annotations:  map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
				Platform:     Platform{OS: "unknown", Architecture: "unknown"},
			},
			{MediaType: MediaTypeInTotoJSON, Digest: "sha256:" + strings.Repeat("5", 64), Size: 1},
			{MediaType: MediaTypeOCIImageIndex, Digest: "sha256:" + strings.Repeat("6", 64), Size: 1},
			{MediaType: MediaTypeOCIEmptyJSON, Digest: "sha256:" + strings.Repeat("7", 64), Size: 2},
			{MediaType: "application/vnd.cncf.helm.config.v1+json", Digest: "sha256:" + strings.Repeat("8", 64), Size: 1, Platform: Platform{OS: "linux", Architecture: "amd64"}},
		},
	}
}

func TestSelectManifestsDefaultsToLinuxAndReportsEverySkippedEntry(t *testing.T) {
	selection, err := SelectManifests(policyTestIndex(), "")
	if err != nil {
		t.Fatalf("SelectManifests() error = %v", err)
	}
	if len(selection.Selected) != 2 || !strings.HasPrefix(selection.Selected[0].Digest, "sha256:111") || !strings.HasPrefix(selection.Selected[1].Digest, "sha256:222") {
		t.Fatalf("selection.Selected = %#v", selection.Selected)
	}
	want := map[string]SkipReason{
		"sha256:" + strings.Repeat("3", 64): SkipReasonPlatform,
		"sha256:" + strings.Repeat("4", 64): SkipReasonUnsupportedManifest,
		"sha256:" + strings.Repeat("5", 64): SkipReasonUnsupportedManifest,
		"sha256:" + strings.Repeat("6", 64): SkipReasonUnsupportedManifest,
		"sha256:" + strings.Repeat("7", 64): SkipReasonUnsupportedManifest,
		"sha256:" + strings.Repeat("8", 64): SkipReasonUnsupportedManifest,
	}
	if len(selection.Skipped) != len(want) {
		t.Fatalf("selection.Skipped = %#v", selection.Skipped)
	}
	for _, skipped := range selection.Skipped {
		reason, ok := want[skipped.Descriptor.Digest]
		if !ok || skipped.Reason != reason {
			t.Fatalf("skipped %s reason = %q, want %q", skipped.Descriptor.Digest, skipped.Reason, reason)
		}
		if strings.TrimSpace(skipped.Detail) == "" {
			t.Fatalf("skipped %s has no detail", skipped.Descriptor.Digest)
		}
		delete(want, skipped.Descriptor.Digest)
	}

	if selected, err := SelectDescriptors(policyTestIndex(), ""); err != nil || len(selected) != 2 {
		t.Fatalf("SelectDescriptors() = %#v, %v", selected, err)
	}
}

func TestSelectManifestsHonoursExplicitSelectors(t *testing.T) {
	tests := []struct {
		selector string
		want     []string
	}{
		{selector: "windows/amd64", want: []string{"sha256:" + strings.Repeat("3", 64)}},
		{selector: "windows", want: []string{"sha256:" + strings.Repeat("3", 64)}},
		{selector: "linux", want: []string{"sha256:" + strings.Repeat("1", 64), "sha256:" + strings.Repeat("2", 64)}},
		{selector: "linux/arm64", want: []string{"sha256:" + strings.Repeat("2", 64)}},
		{selector: "linux/arm64/v8", want: []string{"sha256:" + strings.Repeat("2", 64)}},
		{selector: "linux/amd64/v2", want: []string{"sha256:" + strings.Repeat("1", 64)}},
	}
	for _, test := range tests {
		t.Run(test.selector, func(t *testing.T) {
			selection, err := SelectManifests(policyTestIndex(), test.selector)
			if err != nil {
				t.Fatalf("SelectManifests(%q) error = %v", test.selector, err)
			}
			got := make([]string, 0, len(selection.Selected))
			for _, descriptor := range selection.Selected {
				got = append(got, descriptor.Digest)
			}
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("SelectManifests(%q) = %v, want %v", test.selector, got, test.want)
			}
			for _, skipped := range selection.Skipped {
				if skipped.Reason == SkipReasonPlatform {
					t.Fatalf("explicit selector produced a platform skip: %#v", skipped)
				}
			}
		})
	}

	if _, err := SelectManifests(policyTestIndex(), "linux/riscv64"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("SelectManifests(missing) error = %v", err)
	}
}

func TestSelectManifestsBareArm64SelectorMatchesV8Descriptor(t *testing.T) {
	index := ImageIndex{Manifests: []Descriptor{
		{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("a", 64), Platform: Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("b", 64), Platform: Platform{OS: "linux", Architecture: "arm64"}},
	}}
	for _, selector := range []string{"linux/arm64", "linux/arm64/v8"} {
		selection, err := SelectManifests(index, selector)
		if err != nil || len(selection.Selected) != 2 {
			t.Fatalf("SelectManifests(%q) = %#v, %v", selector, selection, err)
		}
	}
}

func TestSelectManifestsFailsWhenNoLinuxManifestExists(t *testing.T) {
	index := ImageIndex{Manifests: []Descriptor{
		{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("3", 64), Platform: Platform{OS: "windows", Architecture: "amd64"}},
	}}
	_, err := SelectManifests(index, "")
	if err == nil || !strings.Contains(err.Error(), "linux") || IsIntegrityError(err) {
		t.Fatalf("SelectManifests() error = %v", err)
	}

	if _, err := SelectManifests(ImageIndex{Manifests: []Descriptor{{MediaType: MediaTypeInTotoJSON, Digest: "sha256:" + strings.Repeat("5", 64)}}}, ""); err == nil || IsIntegrityError(err) {
		t.Fatalf("SelectManifests(no manifests) error = %v", err)
	}
}

func TestSelectManifestsKeepsPlatformlessImageManifests(t *testing.T) {
	index := ImageIndex{Manifests: []Descriptor{
		{MediaType: MediaTypeOCIImageManifest, Digest: "sha256:" + strings.Repeat("9", 64)},
	}}
	selection, err := SelectManifests(index, "")
	if err != nil || len(selection.Selected) != 1 || len(selection.Skipped) != 0 {
		t.Fatalf("SelectManifests() = %#v, %v", selection, err)
	}
}
