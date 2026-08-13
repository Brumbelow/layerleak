package manifest

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestVerifyDescriptorBytes(t *testing.T) {
	body := []byte("descriptor body")
	digest, err := DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	descriptor := Descriptor{Digest: digest, Size: int64(len(body)), MediaType: MediaTypeOCIImageConfig}
	if err := VerifyDescriptorBytes(descriptor, body, MediaTypeOCIImageConfig+`; charset=utf-8`, true); err != nil {
		t.Fatalf("VerifyDescriptorBytes() error = %v", err)
	}
	if err := VerifyDescriptorBytes(descriptor, body, "application/octet-stream", true); err != nil {
		t.Fatalf("VerifyDescriptorBytes(generic) error = %v", err)
	}
}

func TestVerifyDescriptorBytesRejectsMismatches(t *testing.T) {
	body := []byte("descriptor body")
	digest, _ := DigestBytes("sha256", body)
	tests := []struct {
		name       string
		descriptor Descriptor
		mediaType  string
		kind       IntegrityErrorKind
	}{
		{name: "digest", descriptor: Descriptor{Digest: "sha256:" + strings.Repeat("0", 64), Size: int64(len(body)), MediaType: MediaTypeOCIImageConfig}, mediaType: MediaTypeOCIImageConfig, kind: IntegrityDigestMismatch},
		{name: "size", descriptor: Descriptor{Digest: digest, Size: int64(len(body) + 1), MediaType: MediaTypeOCIImageConfig}, mediaType: MediaTypeOCIImageConfig, kind: IntegritySizeMismatch},
		{name: "media", descriptor: Descriptor{Digest: digest, Size: int64(len(body)), MediaType: MediaTypeOCIImageConfig}, mediaType: MediaTypeOCIImageManifest, kind: IntegrityMediaTypeMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyDescriptorBytes(tt.descriptor, body, tt.mediaType, false)
			var integrityErr *IntegrityError
			if !errors.As(err, &integrityErr) || integrityErr.Kind != tt.kind {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidateDigestErrorsAreIntegrityErrors(t *testing.T) {
	for _, value := range []string{
		" sha256:" + strings.Repeat("0", 64),
		"sha256:not-hex",
		"md5:" + strings.Repeat("0", 32),
	} {
		err := ValidateDigest(value)
		if !IsIntegrityError(err) {
			t.Fatalf("ValidateDigest(%q) error = %v", value, err)
		}
	}
}

func TestValidateDocumentErrorsAreIntegrityErrors(t *testing.T) {
	tests := []Document{
		{Kind: DocumentKindManifest, Manifest: ImageManifest{SchemaVersion: 1, MediaType: MediaTypeOCIImageManifest}},
		{Kind: DocumentKindIndex, Index: ImageIndex{SchemaVersion: 2, MediaType: MediaTypeOCIImageIndex}},
	}
	for _, document := range tests {
		if err := ValidateDocument(document); !IsIntegrityError(err) {
			t.Fatalf("ValidateDocument() error = %v", err)
		}
	}
}

func TestIntegrityErrorEscapesControlCharactersAndBoundsFields(t *testing.T) {
	err := (&IntegrityError{
		Kind:     IntegrityInvalidDigest,
		Subject:  "manifest\nforged\x1b[2J",
		Expected: strings.Repeat("x", 300),
		Actual:   "bad\tdigest",
	}).Error()
	if strings.ContainsAny(err, "\n\r\t\x1b") {
		t.Fatalf("IntegrityError.Error() contains terminal controls: %q", err)
	}
	if !strings.Contains(err, `\n`) || !strings.Contains(err, `\x1b`) || !strings.Contains(err, `\t`) {
		t.Fatalf("IntegrityError.Error() did not escape controls: %q", err)
	}
	if len(err) > 700 {
		t.Fatalf("IntegrityError.Error() is unexpectedly large: %d", len(err))
	}
}

func TestVerifyingReaderVerifiesOnEOF(t *testing.T) {
	body := []byte("streamed descriptor")
	digest, _ := DigestBytes("sha512", body)
	reader, err := NewVerifyingReader(bytes.NewReader(body), Descriptor{Digest: digest, Size: int64(len(body))})
	if err != nil {
		t.Fatalf("NewVerifyingReader() error = %v", err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if err := reader.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyingReaderRejectsExtraBytesBeforeEOF(t *testing.T) {
	body := []byte("streamed descriptor")
	digest, _ := DigestBytes("sha256", body)
	reader, err := NewVerifyingReader(bytes.NewReader(append(append([]byte(nil), body...), 'x')), Descriptor{Digest: digest, Size: int64(len(body))})
	if err != nil {
		t.Fatalf("NewVerifyingReader() error = %v", err)
	}
	_, err = io.ReadAll(reader)
	integrityErr, ok := AsIntegrityError(err)
	if !ok || integrityErr.Kind != IntegritySizeMismatch {
		t.Fatalf("ReadAll() error = %v", err)
	}
}

func FuzzVerifyingReader(f *testing.F) {
	f.Add([]byte("body"), uint8(3))
	f.Add([]byte{}, uint8(1))
	f.Fuzz(func(t *testing.T, body []byte, chunk uint8) {
		digest, err := DigestBytes("sha256", body)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewVerifyingReader(bytes.NewReader(body), Descriptor{Digest: digest, Size: int64(len(body))})
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, int(chunk%32)+1)
		if _, err := io.CopyBuffer(io.Discard, reader, buffer); err != nil {
			t.Fatalf("CopyBuffer() error = %v", err)
		}
		if err := reader.Verify(); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})
}
