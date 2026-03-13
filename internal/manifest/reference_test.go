package manifest

import "testing"

func TestParseReference(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reference
	}{
		{
			name:  "implicit official image",
			input: "ubuntu",
			want: Reference{
				Registry:   DockerHubRegistry,
				Repository: "library/ubuntu",
			},
		},
		{
			name:  "namespaced image with tag",
			input: "bitnami/postgresql:17",
			want: Reference{
				Registry:    DockerHubRegistry,
				Repository:  "bitnami/postgresql",
				Tag:         "17",
				TagExplicit: true,
			},
		},
		{
			name:  "explicit registry with digest",
			input: "docker.io/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: Reference{
				Registry:   DockerHubRegistry,
				Repository: "library/nginx",
				Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name:  "tag and digest",
			input: "registry-1.docker.io/library/busybox:1.36@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: Reference{
				Registry:    DockerHubRegistry,
				Repository:  "library/busybox",
				Tag:         "1.36",
				Digest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				TagExplicit: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseReference(tt.input)
			if err != nil {
				t.Fatalf("ParseReference() error = %v", err)
			}

			if got.Registry != tt.want.Registry {
				t.Fatalf("got.Registry = %q", got.Registry)
			}
			if got.Repository != tt.want.Repository {
				t.Fatalf("got.Repository = %q", got.Repository)
			}
			if got.Tag != tt.want.Tag {
				t.Fatalf("got.Tag = %q", got.Tag)
			}
			if got.Digest != tt.want.Digest {
				t.Fatalf("got.Digest = %q", got.Digest)
			}
			if got.TagExplicit != tt.want.TagExplicit {
				t.Fatalf("got.TagExplicit = %t", got.TagExplicit)
			}
		})
	}
}

func TestParseReferenceRejectsNonDockerHub(t *testing.T) {
	if _, err := ParseReference("ghcr.io/example/app:latest"); err == nil {
		t.Fatal("ParseReference() error = nil")
	}
}

func TestReferenceIdentifierUsesLatestWhenTagMissing(t *testing.T) {
	ref, err := ParseReference("mongo")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	if ref.Identifier() != "latest" {
		t.Fatalf("ref.Identifier() = %q", ref.Identifier())
	}
	if !ref.IsRepositoryOnly() {
		t.Fatal("ref.IsRepositoryOnly() = false")
	}
}
