package manifest

import (
	"errors"
	"strings"
	"testing"
)

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
		{
			name:  "registry-1.docker.io alias keeps library prefix",
			input: "registry-1.docker.io/busybox",
			want: Reference{
				Registry:   DockerHubRegistry,
				Repository: "library/busybox",
			},
		},
		{
			name:  "index.docker.io alias keeps library prefix",
			input: "index.docker.io/busybox:1.36",
			want: Reference{
				Registry:    DockerHubRegistry,
				Repository:  "library/busybox",
				Tag:         "1.36",
				TagExplicit: true,
			},
		},
		{
			name:  "mixed-case docker.io keeps library prefix",
			input: "DOCKER.IO/busybox",
			want: Reference{
				Registry:   DockerHubRegistry,
				Repository: "library/busybox",
			},
		},
		{
			name:  "mixed-case registry-1 alias with namespace",
			input: "Registry-1.Docker.io/bitnami/postgresql:17",
			want: Reference{
				Registry:    DockerHubRegistry,
				Repository:  "bitnami/postgresql",
				Tag:         "17",
				TagExplicit: true,
			},
		},
		{
			name:  "ghcr.io with namespace and tag",
			input: "ghcr.io/homebrew/core/hello:latest",
			want: Reference{
				Registry:    "ghcr.io",
				Repository:  "homebrew/core/hello",
				Tag:         "latest",
				TagExplicit: true,
			},
		},
		{
			name:  "quay.io with tag",
			input: "quay.io/prometheus/busybox:latest",
			want: Reference{
				Registry:    "quay.io",
				Repository:  "prometheus/busybox",
				Tag:         "latest",
				TagExplicit: true,
			},
		},
		{
			name:  "gcr.io distroless",
			input: "gcr.io/distroless/static:nonroot",
			want: Reference{
				Registry:    "gcr.io",
				Repository:  "distroless/static",
				Tag:         "nonroot",
				TagExplicit: true,
			},
		},
		{
			name:  "public.ecr.aws with deep path",
			input: "public.ecr.aws/docker/library/alpine:3.20",
			want: Reference{
				Registry:    "public.ecr.aws",
				Repository:  "docker/library/alpine",
				Tag:         "3.20",
				TagExplicit: true,
			},
		},
		{
			name:  "mcr.microsoft.com single segment repo does not get library prefix",
			input: "mcr.microsoft.com/hello-world",
			want: Reference{
				Registry:   "mcr.microsoft.com",
				Repository: "hello-world",
			},
		},
		{
			name:  "ghcr.io with digest",
			input: "ghcr.io/org/sub/path/image@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			want: Reference{
				Registry:   "ghcr.io",
				Repository: "org/sub/path/image",
				Digest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			},
		},
		{
			name:  "localhost registry with port",
			input: "localhost:5000/foo:dev",
			want: Reference{
				Registry:    "localhost:5000",
				Repository:  "foo",
				Tag:         "dev",
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

func TestDockerHubAliasesShareOneCanonicalString(t *testing.T) {
	want := "docker.io/library/busybox:1.36"
	for _, input := range []string{"busybox:1.36", "library/busybox:1.36", "docker.io/busybox:1.36", "index.docker.io/busybox:1.36", "registry-1.docker.io/busybox:1.36", "DOCKER.IO/library/busybox:1.36"} {
		ref, err := ParseReference(input)
		if err != nil {
			t.Fatalf("ParseReference(%q) error = %v", input, err)
		}
		if got := ref.CanonicalString(""); got != want {
			t.Fatalf("ParseReference(%q).CanonicalString() = %q, want %q", input, got, want)
		}
	}
}

func TestParseReferenceRejectsRegistryWithoutRepository(t *testing.T) {
	if _, err := ParseReference("ghcr.io/"); err == nil {
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

func TestParseReferenceRejectsMalformedValues(t *testing.T) {
	tests := []string{
		" ubuntu",
		"ubuntu ",
		"owner/Image:latest",
		"owner/Image:latest",
		"owner//image:latest",
		"owner/../image:latest",
		`owner\\image:latest`,
		"owner/image?tag=latest",
		"owner/image#latest",
		"owner/image:bad tag",
		"owner/image:tag@sha256:abc",
		"owner/image:tag@md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"owner/image:tag@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaG",
		"ghcr.io:0/owner/image:latest",
		"ghcr.io:65536/owner/image:latest",
		"bad_host.example/owner/image:latest",
		"docker.io/",
		"registry-1.docker.io/",
		"docker.io/UPPER",
		"[2001:db8::1/owner/image:latest",
		"owner/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	for _, value := range tests {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			if _, err := ParseReference(value); err == nil {
				t.Fatalf("ParseReference(%q) error = nil", value)
			}
		})
	}
}

// TestParseReferenceRejectionMessages pins the error each rejection returns
// and which check wins when a value breaks several of them.
func TestParseReferenceRejectionMessages(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "", want: "image reference is required"},
		{value: " oci:/srv/app", want: "image reference must not include surrounding whitespace"},
		{value: "oci:/srv/app?x", want: ErrLocalSourceNotSupported.Error()},
		{value: "https://example.com/image?x", want: "image reference must not include a scheme"},
		{value: "owner/image?x@a@b", want: "image reference contains invalid characters"},
		{value: "owner/image@a@b", want: "image reference must contain at most one digest separator"},
		{value: "ghcr.io/", want: "parse image reference: invalid reference format"},
		{value: "bad_host.example/owner/image", want: "registry host is invalid"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			ref, err := ParseReference(test.value)
			if err == nil || err.Error() != test.want {
				t.Fatalf("ParseReference(%q) error = %v, want %q", test.value, err, test.want)
			}
			if ref != (Reference{}) {
				t.Fatalf("ParseReference(%q) = %#v, want the zero Reference", test.value, ref)
			}
		})
	}
	if _, err := ParseReference("oci:/srv/app"); !errors.Is(err, ErrLocalSourceNotSupported) {
		t.Fatalf("local reference error = %v", err)
	}
	ref, err := ParseReference("owner/image@sha384:" + strings.Repeat("a", 96))
	var integrity *IntegrityError
	if !errors.As(err, &integrity) || integrity.Kind != IntegrityUnsupportedDigestAlgorithm || ref != (Reference{}) {
		t.Fatalf("sha384 digest: ref = %#v, error = %v", ref, err)
	}
}

func TestParseReferenceAcceptsIPv6Registry(t *testing.T) {
	ref, err := ParseReference("[2001:db8::1]:5000/owner/image:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	if ref.Registry != "[2001:db8::1]:5000" {
		t.Fatalf("ref.Registry = %q", ref.Registry)
	}
}

func TestValidateDigest(t *testing.T) {
	if err := ValidateDigest("sha512:" + strings.Repeat("a", 128)); err != nil {
		t.Fatalf("ValidateDigest() error = %v", err)
	}
	if err := ValidateDigest("sha512:" + strings.Repeat("a", 127)); err == nil {
		t.Fatal("ValidateDigest() error = nil")
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"ubuntu",
		"ghcr.io/owner/image:latest",
		"localhost:5000/image@sha256:" + strings.Repeat("a", 64),
		"https://example.com/image",
		"owner/../image",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		ref, err := ParseReference(value)
		if err != nil {
			return
		}
		if ref.Registry == "" || ref.Repository == "" {
			t.Fatalf("accepted incomplete reference: %#v", ref)
		}
		if ref.Digest != "" {
			if err := ValidateDigest(ref.Digest); err != nil {
				t.Fatalf("accepted invalid digest %q: %v", ref.Digest, err)
			}
		}
	})
}
