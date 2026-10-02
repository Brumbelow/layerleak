package manifest

import (
	"errors"
	"strings"
	"testing"
)

const testLocalDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestParseLocalReference(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reference
	}{
		{
			name:  "layout directory without selection",
			input: "oci:/srv/images/app",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/images/app"},
		},
		{
			name:  "layout directory with tag",
			input: "oci:/srv/images/app:1.2",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/images/app", Tag: "1.2", TagExplicit: true},
		},
		{
			name:  "relative layout directory with tag",
			input: "oci:./build/image:latest",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:./build/image", Tag: "latest", TagExplicit: true},
		},
		{
			name:  "path ends at the first colon so a ref.name may hold a slash",
			input: "oci:/srv/a:b/c",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/a", Tag: "b/c", TagExplicit: true},
		},
		{
			name:  "buildx-style ref.name with registry, repository and tag",
			input: "oci:/srv/images/app:docker.io/library/app:1.2",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/images/app", Tag: "docker.io/library/app:1.2", TagExplicit: true},
		},
		{
			name:  "README example: oci archive with name:tag ref.name",
			input: "oci-archive:app.tar:app:1.2",
			want:  Reference{Scheme: SchemeOCIArchive, Registry: LocalRegistry, Repository: "oci-archive:app.tar", Tag: "app:1.2", TagExplicit: true},
		},
		{
			name:  "buildx-style ref.name with digest selection",
			input: "oci-archive:/tmp/app.tar:ghcr.io/org/app:v1@" + testLocalDigest,
			want:  Reference{Scheme: SchemeOCIArchive, Registry: LocalRegistry, Repository: "oci-archive:/tmp/app.tar", Tag: "ghcr.io/org/app:v1", Digest: testLocalDigest, TagExplicit: true},
		},
		{
			name:  "ref.name with a plus sign",
			input: "oci:./out:1.2+build.7",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:./out", Tag: "1.2+build.7", TagExplicit: true},
		},
		{
			name:  "underscore tag from the distribution grammar",
			input: "oci:./out:_private__tag",
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:./out", Tag: "_private__tag", TagExplicit: true},
		},
		{
			name:  "windows drive letter is part of the path",
			input: `oci:C:\images\app:1.2`,
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: `oci:C:\images\app`, Tag: "1.2", TagExplicit: true},
		},
		{
			name:  "windows drive letter without a tag",
			input: `oci-archive:D:/images/app.tar`,
			want:  Reference{Scheme: SchemeOCIArchive, Registry: LocalRegistry, Repository: `oci-archive:D:/images/app.tar`},
		},
		{
			name:  "docker archive on a windows drive",
			input: `docker-archive:C:\images\app.tar:alpine:3.20`,
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: `docker-archive:C:\images\app.tar`, Tag: "alpine:3.20", TagExplicit: true},
		},
		{
			name:  "layout directory with digest",
			input: "oci:/srv/images/app@" + testLocalDigest,
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/images/app", Digest: testLocalDigest},
		},
		{
			name:  "layout directory with tag and digest",
			input: "oci:/srv/images/app:1.2@" + testLocalDigest,
			want:  Reference{Scheme: SchemeOCILayout, Registry: LocalRegistry, Repository: "oci:/srv/images/app", Tag: "1.2", Digest: testLocalDigest, TagExplicit: true},
		},
		{
			name:  "oci archive with tag",
			input: "oci-archive:/tmp/app.tar:1.2",
			want:  Reference{Scheme: SchemeOCIArchive, Registry: LocalRegistry, Repository: "oci-archive:/tmp/app.tar", Tag: "1.2", TagExplicit: true},
		},
		{
			name:  "upper-case scheme is normalised",
			input: "OCI-Archive:/tmp/app.tar",
			want:  Reference{Scheme: SchemeOCIArchive, Registry: LocalRegistry, Repository: "oci-archive:/tmp/app.tar"},
		},
		{
			name:  "docker archive without selection",
			input: "docker-archive:/tmp/app.tar",
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: "docker-archive:/tmp/app.tar"},
		},
		{
			name:  "docker archive with repo and tag",
			input: "docker-archive:/tmp/app.tar:alpine:3.20",
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: "docker-archive:/tmp/app.tar", Tag: "alpine:3.20", TagExplicit: true},
		},
		{
			name:  "docker archive with registry-qualified repo",
			input: "docker-archive:./app.tar:ghcr.io/org/app:v1",
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: "docker-archive:./app.tar", Tag: "ghcr.io/org/app:v1", TagExplicit: true},
		},
		{
			name:  "docker archive with repo only",
			input: "docker-archive:/tmp/app.tar:alpine",
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: "docker-archive:/tmp/app.tar", Tag: "alpine", TagExplicit: true},
		},
		{
			name:  "docker archive with digest",
			input: "docker-archive:/tmp/app.tar@" + testLocalDigest,
			want:  Reference{Scheme: SchemeDockerArchive, Registry: LocalRegistry, Repository: "docker-archive:/tmp/app.tar", Digest: testLocalDigest},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLocalReference(tt.input)
			if err != nil {
				t.Fatalf("ParseLocalReference(%q) error = %v", tt.input, err)
			}
			tt.want.Original = tt.input
			if got != tt.want {
				t.Fatalf("ParseLocalReference(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
			if !got.IsLocal() {
				t.Fatal("IsLocal() = false")
			}
			again, err := ParseImageReference(tt.input)
			if err != nil || again != got {
				t.Fatalf("ParseImageReference(%q) = %+v, %v", tt.input, again, err)
			}
		})
	}
}

func TestParseLocalReferenceRejectsMalformedValues(t *testing.T) {
	tests := []string{
		"oci:",
		"oci-archive:",
		"docker-archive:",
		" oci:/srv/app",
		"oci:/srv/app ",
		"oci:/srv/app:",
		"oci:/srv/app:bad tag",
		"oci:/srv/app:-leading",
		"oci:/srv/app:app::1.2",
		"oci:/srv/app:a//b",
		"oci:/srv/app:/leading/slash",
		"oci:/srv/app:trailing/",
		"oci:/srv/app:docker.io/library/app:1.2:",
		"oci:/srv/app:" + strings.Repeat("a", 300),
		"oci:C:",
		"oci:/srv/app@sha256:abc",
		"oci:/srv/app@md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"oci:/srv/app@" + testLocalDigest + "@" + testLocalDigest,
		"oci:/srv/app\x00",
		"oci:/srv/app\x1b[2J",
		"docker-archive:/tmp/app.tar:",
		"docker-archive:/tmp/app.tar:Upper:tag",
		"docker-archive:/tmp/app.tar:alpine:3.20@sha256:abc",
		"file:/tmp/app.tar",
	}
	for _, value := range tests {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			if _, err := ParseLocalReference(value); err == nil {
				t.Fatalf("ParseLocalReference(%q) error = nil", value)
			}
		})
	}
}

func TestParseReferenceRejectsLocalSourcesWithAClearMessage(t *testing.T) {
	for _, value := range []string{"oci:/srv/app", "oci-archive:/tmp/app.tar:1.2", "docker-archive:./app.tar", "OCI:/srv/app"} {
		_, err := ParseReference(value)
		if !errors.Is(err, ErrLocalSourceNotSupported) {
			t.Fatalf("ParseReference(%q) error = %v", value, err)
		}
		if strings.Contains(err.Error(), value) {
			t.Fatalf("error echoes the caller's value: %v", err)
		}
	}
}

func TestLocalSchemeLeavesRegistryHostsNamedLikeASchemeAlone(t *testing.T) {
	for _, value := range []string{"oci:5000/app:1", "docker-archive:443/org/app", "oci.example/app", "ocidir/app"} {
		if scheme := LocalScheme(value); scheme != "" {
			t.Fatalf("LocalScheme(%q) = %q", value, scheme)
		}
	}
	ref, err := ParseReference("oci:5000/app:1")
	if err != nil || ref.Registry != "oci:5000" || ref.IsLocal() {
		t.Fatalf("ParseReference(oci:5000/app:1) = %+v, %v", ref, err)
	}
}

func TestLocalReferenceRendersInSchemeForm(t *testing.T) {
	ref, err := ParseLocalReference("oci:/srv/images/app:1.2")
	if err != nil {
		t.Fatal(err)
	}
	if got := ref.RepositoryString(); got != "oci:/srv/images/app" {
		t.Fatalf("RepositoryString() = %q", got)
	}
	if got := ref.CanonicalString(""); got != "oci:/srv/images/app:1.2" {
		t.Fatalf("CanonicalString() = %q", got)
	}
	if got := ref.CanonicalString(testLocalDigest); got != "oci:/srv/images/app@"+testLocalDigest {
		t.Fatalf("CanonicalString(digest) = %q", got)
	}
	if got := ref.String(); got != "oci:/srv/images/app:1.2" {
		t.Fatalf("String() = %q", got)
	}
	if got := ref.Identifier(); got != "1.2" {
		t.Fatalf("Identifier() = %q", got)
	}
	withDigest := ref.WithDigest(testLocalDigest)
	if withDigest.Original != "oci:/srv/images/app@"+testLocalDigest || withDigest.Scheme != SchemeOCILayout || withDigest.Registry != LocalRegistry || withDigest.Repository != ref.Repository {
		t.Fatalf("WithDigest() = %+v", withDigest)
	}
	withTag := ref.WithTag("edge")
	if withTag.Original != "oci:/srv/images/app:edge" || withTag.Scheme != SchemeOCILayout || withTag.Tag != "edge" || !withTag.TagExplicit {
		t.Fatalf("WithTag() = %+v", withTag)
	}

	bare, err := ParseLocalReference("docker-archive:/tmp/app.tar")
	if err != nil {
		t.Fatal(err)
	}
	if bare.Identifier() != "" || !bare.IsRepositoryOnly() {
		t.Fatalf("bare local reference: identifier=%q repositoryOnly=%v", bare.Identifier(), bare.IsRepositoryOnly())
	}
	if got := bare.WithTag("alpine:3.20").Original; got != "docker-archive:/tmp/app.tar:alpine:3.20" {
		t.Fatalf("WithTag() = %q", got)
	}
}
