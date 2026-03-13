package manifest

import "testing"

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

func TestConfigFields(t *testing.T) {
	fields := ConfigFields(ImageConfig{
		Author: "builder",
		Config: ImageConfigPayload{
			User:       "root",
			WorkingDir: "/app",
			Cmd:        []string{"run", "server"},
		},
	})

	if len(fields) == 0 {
		t.Fatal("len(fields) = 0")
	}
}
