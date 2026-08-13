package manifest

import (
	"strings"
	"testing"
)

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
