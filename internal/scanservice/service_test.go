package scanservice

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
	"github.com/brumbelow/layerleak/internal/storage"
)

func TestScanAndSavePersistsPartialResultOnLimitError(t *testing.T) {
	firstConfigBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	secondConfigBody := []byte(`{"architecture":"arm64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`)
	firstConfig := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, firstConfigBody)
	secondConfig := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, secondConfigBody)
	firstManifestBody := scanTestManifestBody(t, firstConfig)
	secondManifestBody := scanTestManifestBody(t, secondConfig)
	firstManifest := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, firstManifestBody)
	firstManifest.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	secondManifest := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, secondManifestBody)
	secondManifest.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	indexBody, err := json.Marshal(manifest.ImageIndex{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageIndex,
		Manifests:     []manifest.Descriptor{firstManifest, secondManifest},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	indexDigest := scanTestDescriptor(t, manifest.MediaTypeOCIImageIndex, indexBody).Digest

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return testResponse(http.StatusOK, "application/json", body, nil), nil
		}

		if request.Header.Get("Authorization") != "Bearer test-token" {
			return testResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}

		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, indexBody, map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifest.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifestBody, map[string]string{
				"Docker-Content-Digest": firstManifest.Digest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifest.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifestBody, map[string]string{
				"Docker-Content-Digest": secondManifest.Digest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfig.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfigBody, nil), nil
		case "/v2/library/app/blobs/" + secondConfig.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfigBody, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	store := &recordingStore{}
	service := New(config.Config{
		RegistryBaseURL:         "https://registry.test",
		RegistryAuthURL:         "https://auth.test/token",
		MaxFileBytes:            1 << 20,
		MaxConfigBytes:          128,
		TagPageSize:             100,
		RegistryRequestAttempts: 2,
	}, store)
	service.newRegistryClient = func(options registry.Options) *registry.Client {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: transport}
		return registry.NewClient(options)
	}

	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	outcome, err := service.ScanAndSave(context.Background(), Request{Reference: reference})
	if err == nil {
		t.Fatal("ScanAndSave() error = nil")
	}
	if !limits.IsExceeded(err) {
		t.Fatalf("err = %v", err)
	}
	if outcome.ScanRunID != 1 {
		t.Fatalf("outcome.ScanRunID = %d", outcome.ScanRunID)
	}
	if len(store.records) != 1 {
		t.Fatalf("len(store.records) = %d", len(store.records))
	}
	if outcome.Result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if len(store.records[0].DetailedFindings) == 0 {
		t.Fatal("expected saved partial findings")
	}
	if strings.TrimSpace(store.records[0].Repository) != "library/app" {
		t.Fatalf("store.records[0].Repository = %q", store.records[0].Repository)
	}
}

func TestScanAndSaveLetsBlobTimeoutOwnSlowLayerBody(t *testing.T) {
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	layerBody := scanTestGzipLayer(t, "app/readme.txt", "slow layer")
	layerDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageLayerGzip, layerBody)
	manifestBody, err := json.Marshal(manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        []manifest.Descriptor{layerDescriptor},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	manifestDigest := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponseWithLength(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return testResponseWithLength(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, map[string]string{
				"Docker-Content-Digest": configDescriptor.Digest,
			}), nil
		case "/v2/library/app/blobs/" + layerDescriptor.Digest:
			response := testResponseWithLength(http.StatusOK, manifest.MediaTypeOCIImageLayerGzip, nil, map[string]string{
				"Docker-Content-Digest": layerDescriptor.Digest,
			})
			response.ContentLength = int64(len(layerBody))
			response.Body = &scanDelayedBody{
				ctx:    request.Context(),
				delay:  50 * time.Millisecond,
				reader: bytes.NewReader(layerBody),
			}
			return response, nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	store := &recordingStore{}
	cfg := config.Config{
		RegistryBaseURL:         "https://registry.test",
		HTTPTimeout:             10 * time.Millisecond,
		BlobTimeout:             500 * time.Millisecond,
		MaxFileBytes:            1 << 20,
		MaxConfigBytes:          1 << 20,
		RegistryRequestAttempts: 1,
	}
	service := New(cfg, store)
	var requestTimeout time.Duration
	service.newRegistryClient = func(options registry.Options) *registry.Client {
		requestTimeout = options.RequestTimeout
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: transport}
		return registry.NewClient(options)
	}
	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	outcome, err := service.ScanAndSave(context.Background(), Request{Reference: reference})
	if err != nil {
		t.Fatalf("ScanAndSave() error = %v", err)
	}
	if requestTimeout != cfg.HTTPTimeout {
		t.Fatalf("registry request timeout = %s, want %s", requestTimeout, cfg.HTTPTimeout)
	}
	if outcome.ScanRunID != 1 || len(store.records) != 1 {
		t.Fatalf("outcome/store = %#v/%d", outcome, len(store.records))
	}
}

func TestScanAndSaveAppliesRawFindingPolicy(t *testing.T) {
	secret := "ghp_123456789012345678901234567890123456"
	env := "TOKEN=" + secret
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["` + env + `"]}}`)
	configDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := scanTestManifestBody(t, configDescriptor)
	manifestDigest := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody).Digest

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	reference, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	tests := []struct {
		name               string
		persistRawSecrets  bool
		maxRawFindingBytes int64
		wantRaw            bool
		wantIncomplete     bool
	}{
		{name: "default off"},
		{name: "opt in", persistRawSecrets: true, maxRawFindingBytes: 1 << 20, wantRaw: true},
		{name: "byte limit", persistRawSecrets: true, maxRawFindingBytes: 1, wantIncomplete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingStore{}
			service := New(config.Config{
				RegistryBaseURL:         "https://registry.test",
				MaxFileBytes:            1 << 20,
				MaxConfigBytes:          1 << 20,
				PersistRawSecrets:       test.persistRawSecrets,
				MaxRawFindingBytes:      test.maxRawFindingBytes,
				RegistryRequestAttempts: 1,
			}, store)
			service.newRegistryClient = func(options registry.Options) *registry.Client {
				options.AllowPrivateHosts = true
				options.HTTPClient = &http.Client{Transport: transport}
				return registry.NewClient(options)
			}

			outcome, err := service.ScanAndSave(context.Background(), Request{Reference: reference})
			if test.wantIncomplete {
				if err == nil || !jobs.IsIncomplete(err) {
					t.Fatalf("ScanAndSave() error = %v", err)
				}
				if outcome.Result.Status != jobs.ResultStatusPartial {
					t.Fatalf("outcome.Result.Status = %q", outcome.Result.Status)
				}
				if !scanResultHasDiagnostic(outcome.Result, "max_raw_finding_bytes_exceeded") {
					t.Fatalf("outcome.Result.Diagnostics = %#v", outcome.Result.Diagnostics)
				}
			} else if err != nil {
				t.Fatalf("ScanAndSave() error = %v", err)
			}
			if outcome.ScanRunID != 1 || len(store.records) != 1 {
				t.Fatalf("outcome/store = %#v/%d", outcome, len(store.records))
			}

			outcomeFinding := firstDetailedFinding(t, outcome.Result.DetailedFindings)
			storedFinding := firstDetailedFinding(t, store.records[0].DetailedFindings)
			if test.wantRaw {
				outcomeFinding = detailedFindingByDetector(t, outcome.Result.DetailedFindings, "github_token")
				storedFinding = detailedFindingByDetector(t, store.records[0].DetailedFindings, "github_token")
				if outcomeFinding.Value != secret || outcomeFinding.RawSnippet != env {
					t.Fatalf("outcome raw fields = %q/%q", outcomeFinding.Value, outcomeFinding.RawSnippet)
				}
				if storedFinding.Value != secret || storedFinding.RawSnippet != env {
					t.Fatalf("stored raw fields = %q/%q", storedFinding.Value, storedFinding.RawSnippet)
				}
			} else {
				if outcomeFinding.Value != "" || outcomeFinding.RawSnippet != "" {
					t.Fatalf("outcome retained raw fields = %q/%q", outcomeFinding.Value, outcomeFinding.RawSnippet)
				}
				if storedFinding.Value != "" || storedFinding.RawSnippet != "" {
					t.Fatalf("stored raw fields = %q/%q", storedFinding.Value, storedFinding.RawSnippet)
				}
			}
		})
	}
}

func TestScanAndSaveDoesNotPersistWithCanceledContext(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.context()
			defer cancel()
			store := &contextRejectingStore{}
			service := New(config.Config{}, store)
			reference, err := manifest.ParseReference("library/app:latest")
			if err != nil {
				t.Fatalf("ParseReference() error = %v", err)
			}
			beforeSaveCalled := false

			_, err = service.ScanAndSave(ctx, Request{
				Reference: reference,
				BeforeSave: func(jobs.Result) error {
					beforeSaveCalled = true
					return nil
				},
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("ScanAndSave() error = %v", err)
			}
			if IsSaveError(err) {
				t.Fatalf("ScanAndSave() error was classified as save failure: %v", err)
			}
			if store.calls != 0 || beforeSaveCalled {
				t.Fatalf("persistence attempted: calls=%d before_save=%v", store.calls, beforeSaveCalled)
			}
		})
	}
}

type recordingStore struct {
	records []storage.ScanRecord
}

type contextRejectingStore struct {
	calls int
}

func (s *contextRejectingStore) SaveScan(ctx context.Context, _ storage.ScanRecord) (int64, error) {
	s.calls++
	return 0, ctx.Err()
}

func (s *contextRejectingStore) Name() string {
	return "context-rejecting"
}

func (s *recordingStore) SaveScan(_ context.Context, record storage.ScanRecord) (int64, error) {
	s.records = append(s.records, record)
	return int64(len(s.records)), nil
}

func (s *recordingStore) Name() string {
	return "recording"
}

func detailedFindingByDetector(t *testing.T, items []findings.DetailedFinding, detectorName string) findings.DetailedFinding {
	t.Helper()
	for _, item := range items {
		if item.DetectorName == detectorName {
			return item
		}
	}
	t.Fatalf("detector %q missing from findings: %#v", detectorName, items)
	return findings.DetailedFinding{}
}

func firstDetailedFinding(t *testing.T, items []findings.DetailedFinding) findings.DetailedFinding {
	t.Helper()
	if len(items) == 0 {
		t.Fatal("expected detailed findings")
	}
	return items[0]
}

func scanResultHasDiagnostic(result jobs.Result, code string) bool {
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testResponse(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func testResponseWithLength(statusCode int, contentType string, body []byte, headers map[string]string) *http.Response {
	response := testResponse(statusCode, contentType, body, headers)
	response.ContentLength = int64(len(body))
	return response
}

func scanTestGzipLayer(t *testing.T, name, body string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tarWriter.Write([]byte(body)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzipWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

type scanDelayedBody struct {
	ctx    context.Context
	delay  time.Duration
	reader *bytes.Reader
	waited bool
	closed bool
}

func (b *scanDelayedBody) Read(buffer []byte) (int, error) {
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if !b.waited {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-b.ctx.Done():
			return 0, b.ctx.Err()
		case <-timer.C:
			b.waited = true
		}
	}
	return b.reader.Read(buffer)
}

func (b *scanDelayedBody) Close() error {
	b.closed = true
	return nil
}

func scanTestDescriptor(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("DigestBytes() error = %v", err)
	}
	return manifest.Descriptor{MediaType: mediaType, Digest: digest, Size: int64(len(body))}
}

func scanTestManifestBody(t *testing.T, configDescriptor manifest.Descriptor) []byte {
	t.Helper()
	body, err := json.Marshal(manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        []manifest.Descriptor{},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return body
}
