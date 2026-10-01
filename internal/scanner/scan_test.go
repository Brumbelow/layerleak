package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/layers"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
)

func scanArtifacts(detectorSet detectors.Set, manifestDigest string, platform manifest.Platform, sourceType findings.SourceType, presentInFinalImage bool, artifacts []layers.Artifact) []findings.DetailedFinding {
	return scanArtifactsWithBudget(&detectionBudget{retainRaw: true}, detectorSet, manifestDigest, platform, sourceType, presentInFinalImage, artifacts)
}

func TestScanMultiArchImage(t *testing.T) {
	amd64LayerOne := gzipLayer(t, []tarEntry{
		{name: "app/.env", body: "STRIPE=sk_live_abcdefghijklmnopqrstuvwxyz12"},
		{name: "app/secret.txt", body: "NPM=npm_123456789012345678901234567890123456"},
	})
	amd64LayerTwo := gzipLayer(t, []tarEntry{
		{name: "app/.wh..env", body: ""},
		{name: "app/secret.txt", body: "clean"},
		{name: "app/.docker/config.json", body: `{"auth":"dXNlcjpwYXNz"}`},
	})
	arm64Layer := gzipLayer(t, []tarEntry{
		{name: "root/.netrc", body: "https://user:pass@example.com"},
	})

	attestationDigest := "sha256:9999999999999999999999999999999999999999999999999999999999999999"

	amd64Config := []byte(`{
  "architecture":"amd64",
  "os":"linux",
  "config":{
    "Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],
    "Labels":{"gitlab":"glpat-12345678901234567890"},
    "User":"builder",
    "WorkingDir":"https://builder:realpass123@registry.internal/app"
  },
  "history":[{"created_by":"docker build --build-arg TOKEN=ghp_123456789012345678901234567890123456"}]
}`)
	arm64Config := []byte(`{
  "architecture":"arm64",
  "os":"linux",
  "config":{
    "Env":["AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"],
    "Labels":{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken"}
  }
}`)
	amd64ConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, amd64Config)
	arm64ConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, arm64Config)
	amd64LayerOneDescriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerOne)
	amd64LayerTwoDescriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerTwo)
	arm64LayerDescriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, arm64Layer)
	amd64Manifest := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        amd64ConfigDescriptor,
		Layers:        []manifest.Descriptor{amd64LayerOneDescriptor, amd64LayerTwoDescriptor},
	})
	arm64Manifest := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        arm64ConfigDescriptor,
		Layers:        []manifest.Descriptor{arm64LayerDescriptor},
	})
	amd64ManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, amd64Manifest)
	amd64ManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	arm64ManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, arm64Manifest)
	arm64ManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	index := mustJSON(t, manifest.ImageIndex{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageIndex,
		Manifests: []manifest.Descriptor{
			amd64ManifestDescriptor,
			arm64ManifestDescriptor,
			{
				MediaType:    manifest.MediaTypeOCIImageManifest,
				ArtifactType: "application/vnd.in-toto+json",
				Digest:       attestationDigest,
				Size:         1,
				Annotations:  map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
				Platform:     manifest.Platform{OS: "unknown", Architecture: "unknown"},
			},
		},
	})
	indexDigest := digestFor(t, index)

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, index, map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + amd64ManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, amd64Manifest, map[string]string{
				"Docker-Content-Digest": amd64ManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/manifests/" + arm64ManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, arm64Manifest, map[string]string{
				"Docker-Content-Digest": arm64ManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/blobs/" + amd64ConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, amd64Config, nil), nil
		case "/v2/library/app/blobs/" + arm64ConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, arm64Config, nil), nil
		case "/v2/library/app/blobs/" + amd64LayerOneDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerOne, nil), nil
		case "/v2/library/app/blobs/" + amd64LayerTwoDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, amd64LayerTwo, nil), nil
		case "/v2/library/app/blobs/" + arm64LayerDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, arm64Layer, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	limitedResult, limitedErr := Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		MaxImageManifests: 1,
	})
	if exceeded, ok := limits.AsExceeded(limitedErr); !ok || exceeded.Kind != limits.Kind("image_manifests") {
		t.Fatalf("Scan(manifest limit) result = %#v, error = %v", limitedResult, limitedErr)
	}

	progressUpdates := make([]ProgressUpdate, 0)
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:          detectors.Default(),
		MaxFileBytes:       1 << 20,
		RetainRawSecrets:   true,
		MaxRawFindingBytes: 64 << 20,
		Progress: func(update ProgressUpdate) {
			progressUpdates = append(progressUpdates, update)
		},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.RequestedDigest != indexDigest {
		t.Fatalf("result.RequestedDigest = %q", result.RequestedDigest)
	}
	if result.ManifestCount != 2 {
		t.Fatalf("result.ManifestCount = %d", result.ManifestCount)
	}
	if result.CompletedManifestCount != 2 {
		t.Fatalf("result.CompletedManifestCount = %d", result.CompletedManifestCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if result.UniqueFingerprints == 0 {
		t.Fatal("result.UniqueFingerprints = 0")
	}
	if len(result.DetailedFindings) == 0 {
		t.Fatal("len(result.DetailedFindings) = 0")
	}

	sourceTypes := make([]findings.SourceType, 0, len(result.Findings)+len(result.SuppressedFindings))
	for _, item := range result.Findings {
		sourceTypes = append(sourceTypes, item.SourceType)
	}
	for _, item := range result.SuppressedFindings {
		sourceTypes = append(sourceTypes, item.SourceType)
	}
	for _, expected := range []findings.SourceType{
		findings.SourceTypeEnv,
		findings.SourceTypeLabel,
		findings.SourceTypeHistory,
		findings.SourceTypeConfig,
		findings.SourceTypeFileFinal,
		findings.SourceTypeFileDeletedLayer,
	} {
		if !slices.Contains(sourceTypes, expected) {
			t.Fatalf("missing source type %q", expected)
		}
	}

	foundRaw := false
	for _, item := range result.DetailedFindings {
		if item.Value == "ghp_123456789012345678901234567890123456" && item.SourceLocation == "env:config.env.GH_TOKEN" {
			foundRaw = true
			if !strings.Contains(item.RawSnippet, item.Value) {
				t.Fatalf("item.RawSnippet = %q", item.RawSnippet)
			}
			break
		}
	}
	if !foundRaw {
		t.Fatal("expected raw finding details for env token")
	}
	if len(progressUpdates) == 0 {
		t.Fatal("len(progressUpdates) = 0")
	}
	lastProgress := progressUpdates[len(progressUpdates)-1]
	if lastProgress.Phase != ProgressPhaseCompleted {
		t.Fatalf("lastProgress.Phase = %q", lastProgress.Phase)
	}
	if lastProgress.FindingsFound != result.TotalFindings {
		t.Fatalf("lastProgress.FindingsFound = %d", lastProgress.FindingsFound)
	}
	if lastProgress.ManifestCompleted != result.CompletedManifestCount {
		t.Fatalf("lastProgress.ManifestCompleted = %d", lastProgress.ManifestCompleted)
	}
}

func TestScanArtifactsSkipsNonTextArtifacts(t *testing.T) {
	items := scanArtifacts(
		detectors.Default(),
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		manifest.Platform{OS: "linux", Architecture: "amd64"},
		findings.SourceTypeFileFinal,
		true,
		[]layers.Artifact{
			{
				Path:         "usr/bin/tool",
				LayerDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				ContentClass: layers.ContentClassBinaryELF,
				Scannable:    false,
				Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
			},
			{
				Path:         "app/.env",
				LayerDigest:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				ContentClass: layers.ContentClassText,
				Scannable:    true,
				Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
			},
		},
	)

	if len(items) != 1 {
		t.Fatalf("len(items) = %d", len(items))
	}
	if items[0].FilePath != "app/.env" {
		t.Fatalf("items[0].FilePath = %q", items[0].FilePath)
	}
}

func TestScanArtifactsClassifiesExampleTestDirectories(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		wantDisposition findings.Disposition
	}{
		{name: "test directory", path: "app/test/.env", wantDisposition: findings.DispositionExample},
		{name: "tests directory", path: "app/tests/.env", wantDisposition: findings.DispositionExample},
		{name: "case insensitive directory", path: "app/Test/.env", wantDisposition: findings.DispositionExample},
		{name: "filename remains scannable", path: "app/app_test.go", wantDisposition: findings.DispositionActionable},
		{name: "non test substring remains scannable", path: "app/latest/.env", wantDisposition: findings.DispositionActionable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := scanArtifacts(
				detectors.Default(),
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				manifest.Platform{OS: "linux", Architecture: "amd64"},
				findings.SourceTypeFileFinal,
				true,
				[]layers.Artifact{
					{
						Path:         tt.path,
						LayerDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						ContentClass: layers.ContentClassText,
						Scannable:    true,
						Content:      []byte("TOKEN=ghp_123456789012345678901234567890123456"),
					},
				},
			)

			if len(items) != 1 {
				t.Fatalf("len(items) = %d", len(items))
			}
			if items[0].FilePath != tt.path {
				t.Fatalf("items[0].FilePath = %q", items[0].FilePath)
			}
			if items[0].Disposition != tt.wantDisposition {
				t.Fatalf("items[0].Disposition = %q", items[0].Disposition)
			}
		})
	}
}

func TestScanReturnsUnderlyingManifestFailureWhenAllSelectedManifestsFail(t *testing.T) {
	configDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	manifestBody := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config: manifest.Descriptor{
			MediaType: manifest.MediaTypeOCIImageConfig,
			Digest:    configDigest,
			Size:      1,
		},
		Layers: []manifest.Descriptor{},
	})
	manifestDigest := digestFor(t, manifestBody)

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDigest:
			return testResponse(http.StatusNotFound, "text/plain", []byte("missing config"), nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	_, err = Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "fetch config blob") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "status=404") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanReturnsPartialResultWhenConfigLimitExceededAfterCompletedManifest(t *testing.T) {
	firstConfig := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["VALUE=ghp_123456789012345678901234567890123456"]}}`)
	secondConfig := []byte(`{"architecture":"arm64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`)
	firstConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, firstConfig)
	secondConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, secondConfig)
	firstManifest := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: firstConfigDescriptor, Layers: []manifest.Descriptor{}})
	secondManifest := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: secondConfigDescriptor, Layers: []manifest.Descriptor{}})
	firstManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, firstManifest)
	firstManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	secondManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, secondManifest)
	secondManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	index := mustJSON(t, manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: []manifest.Descriptor{firstManifestDescriptor, secondManifestDescriptor}})
	indexDigest := digestFor(t, index)

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, index, map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifest, map[string]string{
				"Docker-Content-Digest": firstManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifest, map[string]string{
				"Docker-Content-Digest": secondManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfig, nil), nil
		case "/v2/library/app/blobs/" + secondConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfig, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result, err := Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:      detectors.Default(),
		MaxFileBytes:   1 << 20,
		MaxConfigBytes: 128,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "max config bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if result.CompletedManifestCount != 1 {
		t.Fatalf("result.CompletedManifestCount = %d", result.CompletedManifestCount)
	}
	if result.FailedManifestCount != 1 {
		t.Fatalf("result.FailedManifestCount = %d", result.FailedManifestCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
}

func TestScanReturnsEmptyPartialResultWhenConfigLimitExceededBeforeAnyManifestCompletes(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"],"User":"builder","WorkingDir":"https://builder:supersecretvalue@registry.internal/app"}}`)
	configDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, config)
	manifestBody := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configDescriptor, Layers: []manifest.Descriptor{}})
	manifestDigest := digestFor(t, manifestBody)

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, config, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	result, err := Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient: &http.Client{
				Transport: transport,
			},
		}),
		Detectors:      detectors.Default(),
		MaxFileBytes:   1 << 20,
		MaxConfigBytes: 128,
	})
	if err == nil {
		t.Fatal("Scan() error = nil")
	}
	if !strings.Contains(err.Error(), "max config bytes limit") {
		t.Fatalf("err = %v", err)
	}
	if result.CompletedManifestCount != 0 {
		t.Fatalf("result.CompletedManifestCount = %d", result.CompletedManifestCount)
	}
	if result.TotalFindings != 0 {
		t.Fatalf("result.TotalFindings = %d", result.TotalFindings)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("len(result.Findings) = %d", len(result.Findings))
	}
}

func TestScanPreservesMetadataFindingsWhenLayerLimitsExceeded(t *testing.T) {
	layer := gzipLayer(t, []tarEntry{
		{name: "app/one.txt", body: "one"},
		{name: "app/two.txt", body: "two"},
	})
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	configDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, config)
	layerDescriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, layer)
	manifestBody := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configDescriptor, Layers: []manifest.Descriptor{layerDescriptor}})
	manifestDigest := digestFor(t, manifestBody)

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
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, config, nil), nil
		case "/v2/library/app/blobs/" + layerDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeDockerSchema2LayerGzip, layer, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}

	for _, test := range []struct {
		name               string
		maxLayerBytes      int64
		maxImageLayerBytes int64
		wantKind           limits.Kind
	}{
		{name: "per layer", maxLayerBytes: 1536, wantKind: limits.KindLayerBytes},
		{name: "aggregate expanded", maxImageLayerBytes: int64(len(layer)), wantKind: limits.Kind("image_layer_bytes")},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := Scan(context.Background(), Request{
				Reference: ref,
				Registry: registry.MustNewClient(registry.Options{
					BaseURL:           "https://registry.test",
					AllowPrivateHosts: true,
					HTTPClient: &http.Client{
						Transport: transport,
					},
				}),
				Detectors:          detectors.Default(),
				MaxFileBytes:       1 << 20,
				MaxLayerBytes:      test.maxLayerBytes,
				MaxLayerEntries:    50000,
				MaxImageLayerBytes: test.maxImageLayerBytes,
			})
			if err == nil {
				t.Fatal("Scan() error = nil")
			}
			exceeded, ok := limits.AsExceeded(err)
			if !ok || exceeded.Kind != test.wantKind {
				t.Fatalf("err = %v", err)
			}
			if result.CompletedManifestCount != 0 {
				t.Fatalf("result.CompletedManifestCount = %d", result.CompletedManifestCount)
			}
			if result.FailedManifestCount != 1 {
				t.Fatalf("result.FailedManifestCount = %d", result.FailedManifestCount)
			}
			if result.TotalFindings == 0 {
				t.Fatal("result.TotalFindings = 0")
			}
			if len(result.PlatformResults) != 1 {
				t.Fatalf("len(result.PlatformResults) = %d", len(result.PlatformResults))
			}
			if result.PlatformResults[0].FindingsCount == 0 {
				t.Fatalf("result.PlatformResults[0].FindingsCount = %d", result.PlatformResults[0].FindingsCount)
			}
			if !slices.ContainsFunc(result.Findings, func(item findings.Finding) bool {
				return item.SourceType == findings.SourceTypeEnv
			}) {
				t.Fatalf("result.Findings = %#v", result.Findings)
			}
		})
	}
}

func TestScanPreservesBlobDeadlineWhenParentContextIsLive(t *testing.T) {
	firstConfig := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	secondConfig := []byte(`{"architecture":"arm64","os":"linux","config":{}}`)
	layer := gzipLayer(t, []tarEntry{{name: "app/config", body: "clean"}})
	firstConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, firstConfig)
	secondConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, secondConfig)
	layerDescriptor := descriptorFor(t, manifest.MediaTypeDockerSchema2LayerGzip, layer)
	firstManifest := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        firstConfigDescriptor,
		Layers:        []manifest.Descriptor{},
	})
	secondManifest := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        secondConfigDescriptor,
		Layers:        []manifest.Descriptor{layerDescriptor},
	})
	firstManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, firstManifest)
	firstManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	secondManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, secondManifest)
	secondManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	index := mustJSON(t, manifest.ImageIndex{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageIndex,
		Manifests:     []manifest.Descriptor{firstManifestDescriptor, secondManifestDescriptor},
	})
	indexDigest := digestFor(t, index)

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, index, map[string]string{
				"Docker-Content-Digest": indexDigest,
			}), nil
		case "/v2/library/app/manifests/" + firstManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifest, map[string]string{
				"Docker-Content-Digest": firstManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/manifests/" + secondManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifest, map[string]string{
				"Docker-Content-Digest": secondManifestDescriptor.Digest,
			}), nil
		case "/v2/library/app/blobs/" + firstConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfig, nil), nil
		case "/v2/library/app/blobs/" + secondConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfig, nil), nil
		case "/v2/library/app/blobs/" + layerDescriptor.Digest:
			<-request.Context().Done()
			return nil, request.Context().Err()
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	parentCtx := context.Background()
	result, err := Scan(parentCtx, Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			RequestAttempts:   1,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		BlobTimeout:  10 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v", err)
	}
	if parentCtx.Err() != nil {
		t.Fatalf("parentCtx.Err() = %v", parentCtx.Err())
	}
	if result.CompletedManifestCount != 1 || result.FailedManifestCount != 1 {
		t.Fatalf("manifest counts = completed %d, failed %d", result.CompletedManifestCount, result.FailedManifestCount)
	}
	if len(result.PlatformResults) != 2 || !slices.ContainsFunc(result.PlatformResults, func(item PlatformResult) bool {
		return item.Status == ResultStatusFailed
	}) {
		t.Fatalf("result.PlatformResults = %#v", result.PlatformResults)
	}
}

func TestScanPreservesConfigDeadlineWhenParentContextIsLive(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, config)
	manifestBody := mustJSON(t, manifest.ImageManifest{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageManifest,
		Config:        configDescriptor,
		Layers:        []manifest.Descriptor{},
	})
	manifestDigest := digestFor(t, manifestBody)

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, map[string]string{
				"Docker-Content-Digest": manifestDigest,
			}), nil
		case "/v2/library/app/blobs/" + configDescriptor.Digest:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{manifest.MediaTypeOCIImageConfig}},
				Body:       &contextReadCloser{ctx: request.Context()},
			}, nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	parentCtx := context.Background()
	result, err := Scan(parentCtx, Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		Detectors:     detectors.Default(),
		MaxFileBytes:  1 << 20,
		ConfigTimeout: 10 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan() error = %v", err)
	}
	if parentCtx.Err() != nil {
		t.Fatalf("parentCtx.Err() = %v", parentCtx.Err())
	}
	if result.CompletedManifestCount != 0 || result.FailedManifestCount != 1 {
		t.Fatalf("manifest counts = completed %d, failed %d", result.CompletedManifestCount, result.FailedManifestCount)
	}
}

func TestScanMaxFindingsStopsBeforeNextPlatformAtExactBoundary(t *testing.T) {
	firstConfig := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["GH_TOKEN=ghp_123456789012345678901234567890123456"]}}`)
	secondConfig := []byte(`{"architecture":"arm64","os":"linux","config":{}}`)
	firstConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, firstConfig)
	secondConfigDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageConfig, secondConfig)
	firstManifest := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: firstConfigDescriptor, Layers: []manifest.Descriptor{}})
	secondManifest := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: secondConfigDescriptor, Layers: []manifest.Descriptor{}})
	firstManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, firstManifest)
	firstManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	secondManifestDescriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, secondManifest)
	secondManifestDescriptor.Platform = manifest.Platform{OS: "linux", Architecture: "arm64"}
	index := mustJSON(t, manifest.ImageIndex{
		SchemaVersion: 2,
		MediaType:     manifest.MediaTypeOCIImageIndex,
		Manifests:     []manifest.Descriptor{firstManifestDescriptor, secondManifestDescriptor},
	})
	indexDigest := digestFor(t, index)
	secondManifestRequests := 0

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v2/library/app/manifests/latest":
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, index, map[string]string{"Docker-Content-Digest": indexDigest}), nil
		case "/v2/library/app/manifests/" + firstManifestDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, firstManifest, map[string]string{"Docker-Content-Digest": firstManifestDescriptor.Digest}), nil
		case "/v2/library/app/blobs/" + firstConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, firstConfig, nil), nil
		case "/v2/library/app/manifests/" + secondManifestDescriptor.Digest:
			secondManifestRequests++
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, secondManifest, map[string]string{"Docker-Content-Digest": secondManifestDescriptor.Digest}), nil
		case "/v2/library/app/blobs/" + secondConfigDescriptor.Digest:
			return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, secondConfig, nil), nil
		default:
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
	})

	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	result, err := Scan(context.Background(), Request{
		Reference: ref,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: transport},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
		MaxFindings:  1,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.TotalFindings != 1 {
		t.Fatalf("result status/findings = %q/%d", result.Status, result.TotalFindings)
	}
	if result.ManifestCount != 2 || result.CompletedManifestCount != 1 || len(result.PlatformResults) != 1 {
		t.Fatalf("result manifest coverage = count %d, completed %d, results %d", result.ManifestCount, result.CompletedManifestCount, len(result.PlatformResults))
	}
	if !slices.ContainsFunc(result.Diagnostics, func(item Diagnostic) bool { return item.Code == "max_findings_exceeded" }) {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	if secondManifestRequests != 0 {
		t.Fatalf("second manifest requests = %d", secondManifestRequests)
	}
}

func TestDetectionBudgetBoundsRawFindingRetention(t *testing.T) {
	const manifestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	token := "sk-" + "or-v1-" + strings.Repeat("0", 64)
	input := findings.Input{
		ManifestDigest:      manifestDigest,
		SourceType:          findings.SourceTypeFileFinal,
		FilePath:            "app/secrets.txt",
		PresentInFinalImage: true,
		Content:             token,
	}
	scanInput := detectors.ScanInput{Content: token, Path: input.FilePath}

	t.Run("disabled", func(t *testing.T) {
		budget := newDetectionBudget(context.Background(), Request{})
		items := budget.scan(detectors.Default(), input, scanInput)
		if len(items) != 1 {
			t.Fatalf("len(items) = %d", len(items))
		}
		if items[0].Value != "" || items[0].RawSnippet != "" {
			t.Fatalf("raw finding retained by default: %#v", items[0])
		}
		if strings.Contains(items[0].ContextSnippet, token) || strings.Contains(items[0].RedactedValue, token) {
			t.Fatalf("public finding contains token: %#v", items[0].Finding)
		}
		if budget.rawBytes != 0 || budget.rawTruncated {
			t.Fatalf("raw budget = %d, truncated = %t", budget.rawBytes, budget.rawTruncated)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		budget := newDetectionBudget(context.Background(), Request{
			RetainRawSecrets:   true,
			MaxRawFindingBytes: 1 << 20,
		})
		items := budget.scan(detectors.Default(), input, scanInput)
		if len(items) != 1 {
			t.Fatalf("len(items) = %d", len(items))
		}
		if items[0].Value != token || !strings.Contains(items[0].RawSnippet, token) {
			t.Fatalf("raw finding = %#v", items[0])
		}
		wantBytes := int64(len(items[0].Value) + len(items[0].RawSnippet))
		if budget.rawBytes != wantBytes || budget.rawTruncated {
			t.Fatalf("raw budget = %d, want %d, truncated = %t", budget.rawBytes, wantBytes, budget.rawTruncated)
		}
	})

	t.Run("limit", func(t *testing.T) {
		budget := newDetectionBudget(context.Background(), Request{
			RetainRawSecrets:   true,
			MaxRawFindingBytes: 1,
		})
		items := budget.scan(detectors.Default(), input, scanInput)
		if len(items) != 1 {
			t.Fatalf("len(items) = %d", len(items))
		}
		if items[0].Value != "" || items[0].RawSnippet != "" {
			t.Fatalf("over-limit raw finding retained: %#v", items[0])
		}
		// Raw truncation never stops detection; it only disables retention.
		if budget.stopped() || !budget.rawTruncated || budget.rawBytes != 0 || budget.rawTruncatedFindings != 1 {
			t.Fatalf("raw budget = %d, stopped = %t, truncated = %t, truncated findings = %d", budget.rawBytes, budget.stopped(), budget.rawTruncated, budget.rawTruncatedFindings)
		}
		diagnostic := budget.rawDiagnostic()
		if diagnostic.Code != "raw_retention_truncated" || diagnostic.Limit != 1 || diagnostic.Observed <= diagnostic.Limit || diagnostic.Subject != manifestDigest {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
		later := budget.scan(detectors.Default(), input, scanInput)
		if len(later) != 1 || later[0].Value != "" || later[0].RawSnippet != "" {
			t.Fatalf("later = %#v", later)
		}
		if budget.rawTruncatedFindings != 2 || budget.retained != 2 {
			t.Fatalf("budget = %#v", budget)
		}
	})
}

func TestDetectionBudgetRedactsDifferentSecretInFilePathWithoutEmittingFinding(t *testing.T) {
	contentSecret := "ghp_123456789012345678901234567890123456"
	pathSecret := "sk-" + "or-v1-" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name     string
		filePath string
	}{
		{name: "short", filePath: "secrets/" + pathSecret + "/config"},
		{name: "long", filePath: strings.Repeat("nested/", 80) + pathSecret + "/config"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := findings.Input{
				ManifestDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				SourceType:          findings.SourceTypeFileFinal,
				FilePath:            test.filePath,
				PresentInFinalImage: true,
				Content:             contentSecret,
			}

			budget := newDetectionBudget(context.Background(), Request{})
			items := budget.scan(detectors.Default(), input, detectors.ScanInput{
				Content: input.Content,
				Path:    input.FilePath,
			})
			if len(items) != 1 {
				t.Fatalf("len(items) = %d", len(items))
			}
			if items[0].Value != "" || items[0].Fingerprint != findings.Fingerprint(contentSecret) {
				t.Fatalf("finding represents provenance-only secret: %#v", items[0])
			}
			for field, value := range map[string]string{
				"file path":       items[0].FilePath,
				"source location": items[0].SourceLocation,
			} {
				if strings.Contains(value, pathSecret) {
					t.Fatalf("%s leaked path secret: %q", field, value)
				}
			}
			if budget.retained != 1 {
				t.Fatalf("budget.retained = %d", budget.retained)
			}
			if test.name == "short" && !strings.Contains(items[0].FilePath, "[REDACTED]") {
				t.Fatalf("items[0].FilePath = %q", items[0].FilePath)
			}
			if test.name == "long" {
				redacted := strings.Replace(test.filePath, pathSecret, "[REDACTED]", 1)
				rawHash := findings.Fingerprint(test.filePath)
				redactedHash := findings.Fingerprint(redacted)
				if strings.Contains(items[0].FilePath, rawHash) || !strings.Contains(items[0].FilePath, redactedHash) {
					t.Fatalf("items[0].FilePath used the wrong truncation hash: %q", items[0].FilePath)
				}
			}
		})
	}
}

func TestScanMetadataKeepsCurrentAndLegacyConfigProvenanceDistinct(t *testing.T) {
	const token = "ghp_123456789012345678901234567890123456"
	imageConfig := manifest.ImageConfig{
		Config: manifest.ImageConfigPayload{
			Env:         []string{"GH_TOKEN=" + token},
			Labels:      map[string]string{"token": token},
			Healthcheck: manifest.Healthcheck{Test: []string{"CMD-SHELL", "check " + token}},
		},
		ContainerConfig: manifest.ImageConfigPayload{
			Env:         []string{"GH_TOKEN=" + token},
			Labels:      map[string]string{"token": token},
			Healthcheck: manifest.Healthcheck{Test: []string{"CMD-SHELL", "check " + token}},
		},
	}

	items := findings.DeduplicateDetailed(scanMetadataWithBudget(
		&detectionBudget{retainRaw: true},
		detectors.Default(),
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		manifest.Platform{OS: "linux", Architecture: "amd64"},
		imageConfig,
	))
	locations := make(map[string]findings.SourceType, len(items))
	for _, item := range items {
		if item.Value == token {
			locations[item.SourceLocation] = item.SourceType
		}
	}

	want := map[string]findings.SourceType{
		"env:config.env.GH_TOKEN":                     findings.SourceTypeEnv,
		"label:config.label.token":                    findings.SourceTypeLabel,
		"config:config.healthcheck.test[1]":           findings.SourceTypeConfig,
		"env:container_config.env.GH_TOKEN":           findings.SourceTypeEnv,
		"label:container_config.label.token":          findings.SourceTypeLabel,
		"config:container_config.healthcheck.test[1]": findings.SourceTypeConfig,
	}
	for location, sourceType := range want {
		if locations[location] != sourceType {
			t.Errorf("finding %q source type = %q, want %q", location, locations[location], sourceType)
		}
	}
	if len(locations) != len(want) {
		t.Fatalf("locations = %#v", locations)
	}
}

// registryFixture serves an in-memory repository (library/app) through the
// bearer-token handshake the other scanner tests use, and counts requests.
type registryFixture struct {
	routes   map[string][]byte
	types    map[string]string
	digests  map[string]string
	requests map[string]int
}

func newRegistryFixture() *registryFixture {
	return &registryFixture{
		routes:   map[string][]byte{},
		types:    map[string]string{},
		digests:  map[string]string{},
		requests: map[string]int{},
	}
}

func (f *registryFixture) transport() roundTripFunc {
	return func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return testResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			return testResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
			}), nil
		}
		f.requests[request.URL.Path]++
		body, ok := f.routes[request.URL.Path]
		if !ok {
			return testResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
		}
		headers := map[string]string{}
		if digest, ok := f.digests[request.URL.Path]; ok {
			headers["Docker-Content-Digest"] = digest
		}
		return testResponse(http.StatusOK, f.types[request.URL.Path], body, headers), nil
	}
}

func (f *registryFixture) blob(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	descriptor := descriptorFor(t, mediaType, body)
	f.routes["/v2/library/app/blobs/"+descriptor.Digest] = body
	f.types["/v2/library/app/blobs/"+descriptor.Digest] = mediaType
	return descriptor
}

func (f *registryFixture) imageManifest(t *testing.T, config manifest.Descriptor, layers []manifest.Descriptor, platform manifest.Platform) manifest.Descriptor {
	t.Helper()
	body := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: config, Layers: layers})
	descriptor := descriptorFor(t, manifest.MediaTypeOCIImageManifest, body)
	descriptor.Platform = platform
	path := "/v2/library/app/manifests/" + descriptor.Digest
	f.routes[path] = body
	f.types[path] = manifest.MediaTypeOCIImageManifest
	f.digests[path] = descriptor.Digest
	return descriptor
}

func (f *registryFixture) setIndex(t *testing.T, descriptors ...manifest.Descriptor) string {
	t.Helper()
	body := mustJSON(t, manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: descriptors})
	f.routes["/v2/library/app/manifests/latest"] = body
	f.types["/v2/library/app/manifests/latest"] = manifest.MediaTypeOCIImageIndex
	f.digests["/v2/library/app/manifests/latest"] = digestFor(t, body)
	return f.digests["/v2/library/app/manifests/latest"]
}

func (f *registryFixture) setRootManifest(t *testing.T, config manifest.Descriptor, layers []manifest.Descriptor) string {
	t.Helper()
	body := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: config, Layers: layers})
	f.routes["/v2/library/app/manifests/latest"] = body
	f.types["/v2/library/app/manifests/latest"] = manifest.MediaTypeOCIImageManifest
	f.digests["/v2/library/app/manifests/latest"] = digestFor(t, body)
	return f.digests["/v2/library/app/manifests/latest"]
}

func (f *registryFixture) request(t *testing.T, platform string) Request {
	t.Helper()
	ref, err := manifest.ParseReference("library/app:latest")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	return Request{
		Reference: ref,
		Platform:  platform,
		Registry: registry.MustNewClient(registry.Options{
			BaseURL:           "https://registry.test",
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{Transport: f.transport()},
		}),
		Detectors:    detectors.Default(),
		MaxFileBytes: 1 << 20,
	}
}

func configBlob(t *testing.T, f *registryFixture, os, architecture string, env ...string) manifest.Descriptor {
	t.Helper()
	body := mustJSON(t, map[string]any{
		"architecture": architecture,
		"os":           os,
		"config":       map[string]any{"Env": env},
	})
	return f.blob(t, manifest.MediaTypeOCIImageConfig, body)
}

// foreignLayer is a Windows-style non-distributable base layer. It is never
// fetched, so no blob route exists for it.
func foreignLayer() manifest.Descriptor {
	return manifest.Descriptor{
		MediaType: manifest.MediaTypeDockerSchema2ForeignLayerGzip,
		Digest:    "sha256:" + strings.Repeat("f", 64),
		Size:      10,
		URLs:      []string{"https://example.invalid/foreign-layer"},
	}
}

func diagnosticCodes(items []Diagnostic) []string {
	codes := make([]string, 0, len(items))
	for _, item := range items {
		codes = append(codes, item.Code)
	}
	return codes
}

func findDiagnostic(items []Diagnostic, code, subject string) (Diagnostic, bool) {
	for _, item := range items {
		if item.Code == code && (subject == "" || item.Subject == subject) {
			return item, true
		}
	}
	return Diagnostic{}, false
}

const syntheticGitHubToken = "ghp_123456789012345678901234567890123456"

func TestScanDefaultsToLinuxManifestsAndReportsSkippedEntries(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	windows := f.imageManifest(t, configBlob(t, f, "windows", "amd64"), []manifest.Descriptor{foreignLayer()}, manifest.Platform{OS: "windows", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	attestation := manifest.Descriptor{
		MediaType:    manifest.MediaTypeOCIImageManifest,
		ArtifactType: manifest.MediaTypeInTotoJSON,
		Digest:       "sha256:" + strings.Repeat("9", 64),
		Size:         1,
		Annotations:  map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		Platform:     manifest.Platform{OS: "unknown", Architecture: "unknown"},
	}
	inToto := manifest.Descriptor{MediaType: manifest.MediaTypeInTotoJSON, Digest: "sha256:" + strings.Repeat("8", 64), Size: 1}
	f.setIndex(t, amd64, windows, arm64, attestation, inToto)

	result, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || !result.Coverage.Complete {
		t.Fatalf("result status = %q, coverage = %#v", result.Status, result.Coverage)
	}
	if result.ManifestCount != 2 || result.CompletedManifestCount != 2 || result.FailedManifestCount != 0 {
		t.Fatalf("manifest counts = %d/%d/%d", result.ManifestCount, result.CompletedManifestCount, result.FailedManifestCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("result.TotalFindings = 0")
	}
	if _, ok := findDiagnostic(result.Diagnostics, "platform_skipped", windows.Digest); !ok {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	for _, digest := range []string{attestation.Digest, inToto.Digest} {
		if _, ok := findDiagnostic(result.Diagnostics, "manifest_skipped", digest); !ok {
			t.Fatalf("missing manifest_skipped for %s: %#v", digest, result.Diagnostics)
		}
	}
	if f.requests["/v2/library/app/manifests/"+windows.Digest] != 0 {
		t.Fatal("the skipped windows manifest was fetched")
	}
	for _, platform := range result.PlatformResults {
		if platform.Platform.OS != "linux" || platform.Status != ResultStatusCompleted {
			t.Fatalf("platform result = %#v", platform)
		}
	}
}

func TestScanReportsUnsupportedManifestAsPartialAndContinues(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	// The unscannable manifest comes first so the test proves the remaining
	// platform still runs. Its config carries a metadata finding that must survive.
	foreign := f.imageManifest(t, configBlob(t, f, "linux", "arm64", "TOKEN="+syntheticGitHubToken), []manifest.Descriptor{foreignLayer()}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	f.setIndex(t, foreign, amd64)

	result, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.CompletedManifestCount != 1 || result.FailedManifestCount != 1 {
		t.Fatalf("result = status %q, completed %d, failed %d", result.Status, result.CompletedManifestCount, result.FailedManifestCount)
	}
	if len(result.PlatformResults) != 2 {
		t.Fatalf("result.PlatformResults = %#v", result.PlatformResults)
	}
	var unsupported PlatformResult
	for _, platform := range result.PlatformResults {
		if platform.ManifestDigest == foreign.Digest {
			unsupported = platform
		}
	}
	if unsupported.Status != ResultStatusFailed || !strings.Contains(unsupported.Error, "cannot be scanned") {
		t.Fatalf("unsupported platform result = %#v", unsupported)
	}
	if _, ok := findDiagnostic(unsupported.Diagnostics, "manifest_unsupported", foreign.Digest); !ok {
		t.Fatalf("unsupported platform diagnostics = %#v", unsupported.Diagnostics)
	}
	if _, ok := findDiagnostic(result.Diagnostics, "descriptor_media_type_mismatch", ""); ok {
		t.Fatalf("unsupported manifest was reported as an integrity failure: %#v", result.Diagnostics)
	}
	if unsupported.FindingsCount == 0 {
		t.Fatal("metadata findings of the unsupported manifest were lost")
	}
	if f.requests["/v2/library/app/blobs/"+foreignLayer().Digest] != 0 {
		t.Fatal("a foreign layer blob was requested")
	}
}

func TestScanAttemptsExplicitlySelectedNonLinuxManifest(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	windows := f.imageManifest(t, configBlob(t, f, "windows", "amd64"), []manifest.Descriptor{foreignLayer()}, manifest.Platform{OS: "windows", Architecture: "amd64"})
	f.setIndex(t, amd64, windows)

	result, err := Scan(context.Background(), f.request(t, "windows/amd64"))
	if err == nil || !IsUnsupportedManifest(err) {
		t.Fatalf("Scan() error = %v", err)
	}
	if manifest.IsIntegrityError(err) || limits.IsExceeded(err) {
		t.Fatalf("unsupported manifest classified as integrity or limit failure: %v", err)
	}
	if result.Status != ResultStatusFailed || result.ManifestCount != 1 || len(result.PlatformResults) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if _, ok := findDiagnostic(result.Diagnostics, "manifest_unsupported", windows.Digest); !ok {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	if f.requests["/v2/library/app/manifests/"+windows.Digest] == 0 {
		t.Fatal("the explicitly selected windows manifest was not attempted")
	}
}

func TestScanSingleManifestRootHonoursPlatformSelector(t *testing.T) {
	build := func(t *testing.T) *registryFixture {
		f := newRegistryFixture()
		layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
		f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer})
		return f
	}

	t.Run("mismatch", func(t *testing.T) {
		f := build(t)
		result, err := Scan(context.Background(), f.request(t, "linux/arm64"))
		if err == nil || !IsPlatformNotFound(err) || !strings.Contains(err.Error(), "linux/arm64") {
			t.Fatalf("Scan() error = %v", err)
		}
		if result.Status != ResultStatusFailed || result.CompletedManifestCount != 0 || result.TotalFindings != 0 {
			t.Fatalf("result = status %q, completed %d, findings %d", result.Status, result.CompletedManifestCount, result.TotalFindings)
		}
		if _, ok := findDiagnostic(result.Diagnostics, "platform_not_found", ""); !ok {
			t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
		}
		if manifest.IsIntegrityError(err) {
			t.Fatalf("selector mismatch classified as integrity failure: %v", err)
		}
	})

	for _, selector := range []string{"", "linux", "linux/amd64", "linux/amd64/v3"} {
		t.Run("match "+selector, func(t *testing.T) {
			f := build(t)
			result, err := Scan(context.Background(), f.request(t, selector))
			if err != nil {
				t.Fatalf("Scan(%q) error = %v", selector, err)
			}
			if result.Status != ResultStatusCompleted || result.TotalFindings == 0 {
				t.Fatalf("Scan(%q) result = status %q, findings %d", selector, result.Status, result.TotalFindings)
			}
		})
	}
}

func TestScanAcceptsOSOnlyAndVariantNormalisedSelectors(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/config", body: "clean"}}))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	windows := f.imageManifest(t, configBlob(t, f, "windows", "amd64"), []manifest.Descriptor{foreignLayer()}, manifest.Platform{OS: "windows", Architecture: "amd64"})
	f.setIndex(t, amd64, arm64, windows)

	for _, test := range []struct {
		selector string
		want     []string
	}{
		{selector: "linux", want: []string{amd64.Digest, arm64.Digest}},
		{selector: "linux/arm64/v8", want: []string{arm64.Digest}},
		{selector: "linux/arm64", want: []string{arm64.Digest}},
	} {
		t.Run(test.selector, func(t *testing.T) {
			result, err := Scan(context.Background(), f.request(t, test.selector))
			if err != nil {
				t.Fatalf("Scan(%q) error = %v", test.selector, err)
			}
			if result.Status != ResultStatusCompleted || result.CompletedManifestCount != len(test.want) {
				t.Fatalf("Scan(%q) = status %q, completed %d", test.selector, result.Status, result.CompletedManifestCount)
			}
			for _, digest := range test.want {
				if !slices.ContainsFunc(result.PlatformResults, func(item PlatformResult) bool { return item.ManifestDigest == digest }) {
					t.Fatalf("Scan(%q) missing platform %s: %#v", test.selector, digest, result.PlatformResults)
				}
			}
			if slices.Contains(diagnosticCodes(result.Diagnostics), "platform_skipped") {
				t.Fatalf("explicit selector produced platform_skipped: %#v", result.Diagnostics)
			}
		})
	}
}

func TestScanFindingsBudgetExhaustedOnEntryYieldsPartialResult(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	config := configBlob(t, f, "linux", "amd64")
	f.setRootManifest(t, config, []manifest.Descriptor{layer})

	request := f.request(t, "")
	request.MaxFindings = 5
	request.ExistingFindings = 5
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.Coverage.Complete {
		t.Fatalf("result status = %q, coverage = %#v", result.Status, result.Coverage)
	}
	if result.ManifestCount != 1 || result.CompletedManifestCount != 0 || result.FailedManifestCount != 0 || len(result.PlatformResults) != 0 {
		t.Fatalf("result counts = %d/%d/%d, platforms %d", result.ManifestCount, result.CompletedManifestCount, result.FailedManifestCount, len(result.PlatformResults))
	}
	if codes := diagnosticCodes(result.Diagnostics); len(codes) != 1 || codes[0] != "max_findings_exceeded" {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	if f.requests["/v2/library/app/blobs/"+config.Digest] != 0 || f.requests["/v2/library/app/blobs/"+layer.Digest] != 0 {
		t.Fatalf("blobs were fetched for an exhausted budget: %#v", f.requests)
	}
}

func TestScanReportsBudgetDiagnosticsOnce(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: strings.Join([]string{
		"A=ghp_123456789012345678901234567890123456",
		"B=ghp_223456789012345678901234567890123456",
		"C=ghp_323456789012345678901234567890123456",
	}, "\n")}}))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	f.setIndex(t, amd64, arm64)

	request := f.request(t, "")
	request.MaxFindings = 2
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.TotalFindings != 2 || result.CompletedManifestCount != 1 {
		t.Fatalf("result = status %q, findings %d, completed %d", result.Status, result.TotalFindings, result.CompletedManifestCount)
	}
	count := 0
	for _, code := range diagnosticCodes(result.Diagnostics) {
		if code == "max_findings_exceeded" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("max_findings_exceeded reported %d times: %#v", count, result.Diagnostics)
	}
}

func TestScanContinuesDetectionWhenRawRetentionBudgetIsExhausted(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{
		{name: "app/first.env", body: "A=ghp_123456789012345678901234567890123456"},
		{name: "app/second.env", body: "B=ghp_223456789012345678901234567890123456"},
	}))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{layer}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	f.setIndex(t, amd64, arm64)

	request := f.request(t, "")
	request.RetainRawSecrets = true
	request.MaxRawFindingBytes = 1
	result, err := Scan(context.Background(), request)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusCompleted || !result.Coverage.Complete {
		t.Fatalf("result status = %q, coverage = %#v", result.Status, result.Coverage)
	}
	if result.CompletedManifestCount != 2 || result.TotalFindings != 4 {
		t.Fatalf("result = completed %d, findings %d", result.CompletedManifestCount, result.TotalFindings)
	}
	for _, item := range result.DetailedFindings {
		if item.Value != "" || item.RawSnippet != "" {
			t.Fatalf("raw value retained beyond the budget: %#v", item)
		}
	}
	codes := diagnosticCodes(result.Diagnostics)
	if slices.Contains(codes, "max_raw_finding_bytes_exceeded") {
		t.Fatalf("raw budget still reported as a coverage failure: %#v", result.Diagnostics)
	}
	truncated := 0
	for _, code := range codes {
		if code == "raw_retention_truncated" {
			truncated++
		}
	}
	if truncated != 1 {
		t.Fatalf("raw_retention_truncated reported %d times: %#v", truncated, result.Diagnostics)
	}
	diagnostic, _ := findDiagnostic(result.Diagnostics, "raw_retention_truncated", "")
	if diagnostic.Limit != 1 || diagnostic.Observed <= diagnostic.Limit || diagnostic.Scope != "scan" {
		t.Fatalf("raw_retention_truncated diagnostic = %#v", diagnostic)
	}
	for _, platform := range result.PlatformResults {
		if platform.Status != ResultStatusCompleted || platform.FindingsCount != 2 {
			t.Fatalf("platform result = %#v", platform)
		}
	}
}

// cancellingBody serves a prefix of a blob, cancels the scan context and then
// fails every further read, simulating an operator interrupt mid-layer.
type cancellingBody struct {
	reader *bytes.Reader
	cancel context.CancelFunc
	ctx    context.Context
	served bool
}

func (b *cancellingBody) Read(p []byte) (int, error) {
	if b.served {
		<-b.ctx.Done()
		return 0, b.ctx.Err()
	}
	b.served = true
	if len(p) > 16 {
		p = p[:16]
	}
	n, err := b.reader.Read(p)
	b.cancel()
	return n, err
}

func (b *cancellingBody) Close() error { return nil }

func TestScanCancellationMidLayerYieldsScanCanceledAndKeepsCompletedFindings(t *testing.T) {
	f := newRegistryFixture()
	clean := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	slowLayer := gzipLayer(t, []tarEntry{{name: "app/other", body: "other"}})
	slow := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, slowLayer)
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{clean}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{slow}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	f.setIndex(t, amd64, arm64)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := f.transport()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v2/library/app/blobs/"+slow.Digest && request.Header.Get("Authorization") == "Bearer test-token" {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{manifest.MediaTypeDockerSchema2LayerGzip}},
				Body:          &cancellingBody{reader: bytes.NewReader(slowLayer), cancel: cancel, ctx: ctx},
				ContentLength: -1,
			}, nil
		}
		return inner(request)
	})
	request := f.request(t, "")
	request.Registry = registry.MustNewClient(registry.Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})

	result, err := Scan(ctx, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.CompletedManifestCount != 1 || result.FailedManifestCount != 1 {
		t.Fatalf("result = status %q, completed %d, failed %d", result.Status, result.CompletedManifestCount, result.FailedManifestCount)
	}
	if result.TotalFindings == 0 {
		t.Fatal("findings from the completed platform were lost")
	}
	if _, ok := findDiagnostic(result.Diagnostics, "scan_canceled", arm64.Digest); !ok {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	for _, platform := range result.PlatformResults {
		if platform.ManifestDigest == arm64.Digest && (platform.Status != ResultStatusFailed || platform.Coverage.LayersCompleted != 0) {
			t.Fatalf("cancelled platform = %#v", platform)
		}
	}
}

func TestScanManifestWithRepeatedLayerDigestIsDeterministic(t *testing.T) {
	f := newRegistryFixture()
	layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/.env", body: "GH=" + syntheticGitHubToken}}))
	f.setRootManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{layer, layer})

	first, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if f.requests["/v2/library/app/blobs/"+layer.Digest] != 2 {
		t.Fatalf("layer blob requested %d times, want 2", f.requests["/v2/library/app/blobs/"+layer.Digest])
	}
	second, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if first.Status != ResultStatusCompleted || first.TotalFindings == 0 || first.Coverage.LayersCompleted != 2 {
		t.Fatalf("first = %#v", first)
	}
	if !reflect.DeepEqual(first.Findings, second.Findings) || !reflect.DeepEqual(first.Coverage, second.Coverage) || !reflect.DeepEqual(first.Diagnostics, second.Diagnostics) {
		t.Fatalf("repeated layer digest scanned non-deterministically:\n%#v\n%#v", first, second)
	}
}

func TestScanReportsTrailingLayerDataUnderDedicatedDiagnostic(t *testing.T) {
	f := newRegistryFixture()
	clean := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/config", body: "clean"}}))
	trailing := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, append(gzipLayer(t, []tarEntry{{name: "app/other", body: "other"}}), make([]byte, 512)...))
	amd64 := f.imageManifest(t, configBlob(t, f, "linux", "amd64"), []manifest.Descriptor{clean}, manifest.Platform{OS: "linux", Architecture: "amd64"})
	arm64 := f.imageManifest(t, configBlob(t, f, "linux", "arm64"), []manifest.Descriptor{trailing}, manifest.Platform{OS: "linux", Architecture: "arm64"})
	f.setIndex(t, amd64, arm64)

	result, err := Scan(context.Background(), f.request(t, ""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Status != ResultStatusPartial || result.CompletedManifestCount != 1 || result.FailedManifestCount != 1 {
		t.Fatalf("result = status %q, completed %d, failed %d", result.Status, result.CompletedManifestCount, result.FailedManifestCount)
	}
	diagnostic, ok := findDiagnostic(result.Diagnostics, "layer_trailing_data", arm64.Digest)
	if !ok || !strings.Contains(diagnostic.Message, "trailing data") {
		t.Fatalf("result.Diagnostics = %#v", result.Diagnostics)
	}
	if _, ok := findDiagnostic(result.Diagnostics, "manifest_failed", ""); ok {
		t.Fatalf("trailing data was reported under the generic code: %#v", result.Diagnostics)
	}
}

func TestScanVerifiesRootDigestBeforeParsing(t *testing.T) {
	// Syntactically broken JSON: if the body were decoded first the failure
	// would be invalid_manifest_document; the digest check must win.
	malformed := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [}`)
	const latest = "/v2/library/app/manifests/latest"

	t.Run("digest reference", func(t *testing.T) {
		f := newRegistryFixture()
		expected := "sha256:" + strings.Repeat("a", 64)
		f.routes["/v2/library/app/manifests/"+expected] = malformed
		f.types["/v2/library/app/manifests/"+expected] = manifest.MediaTypeOCIImageManifest
		ref, err := manifest.ParseReference("library/app@" + expected)
		if err != nil {
			t.Fatalf("ParseReference() error = %v", err)
		}
		request := f.request(t, "")
		request.Reference = ref
		_, err = Scan(context.Background(), request)
		integrityErr, ok := manifest.AsIntegrityError(err)
		if !ok || integrityErr.Kind != manifest.IntegrityDigestMismatch {
			t.Fatalf("Scan() error = %v, want %s", err, manifest.IntegrityDigestMismatch)
		}
	})

	t.Run("tag reference with registry digest", func(t *testing.T) {
		f := newRegistryFixture()
		f.routes[latest] = malformed
		f.types[latest] = manifest.MediaTypeOCIImageManifest
		f.digests[latest] = "sha256:" + strings.Repeat("b", 64)
		_, err := Scan(context.Background(), f.request(t, ""))
		integrityErr, ok := manifest.AsIntegrityError(err)
		if !ok || integrityErr.Kind != manifest.IntegrityDigestMismatch {
			t.Fatalf("Scan() error = %v, want %s", err, manifest.IntegrityDigestMismatch)
		}
	})

	t.Run("tag reference without registry digest", func(t *testing.T) {
		f := newRegistryFixture()
		f.routes[latest] = malformed
		f.types[latest] = manifest.MediaTypeOCIImageManifest
		_, err := Scan(context.Background(), f.request(t, ""))
		integrityErr, ok := manifest.AsIntegrityError(err)
		if !ok || integrityErr.Kind != manifest.IntegrityInvalidDocument {
			t.Fatalf("Scan() error = %v, want %s", err, manifest.IntegrityInvalidDocument)
		}
	})

	t.Run("digest reference with matching body", func(t *testing.T) {
		f := newRegistryFixture()
		layer := f.blob(t, manifest.MediaTypeDockerSchema2LayerGzip, gzipLayer(t, []tarEntry{{name: "app/config", body: "clean"}}))
		body := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configBlob(t, f, "linux", "amd64"), Layers: []manifest.Descriptor{layer}})
		digest := digestFor(t, body)
		f.routes["/v2/library/app/manifests/"+digest] = body
		f.types["/v2/library/app/manifests/"+digest] = manifest.MediaTypeOCIImageManifest
		ref, err := manifest.ParseReference("library/app@" + digest)
		if err != nil {
			t.Fatalf("ParseReference() error = %v", err)
		}
		request := f.request(t, "")
		request.Reference = ref
		result, err := Scan(context.Background(), request)
		if err != nil || result.Status != ResultStatusCompleted || result.RequestedDigest != digest {
			t.Fatalf("Scan() = %#v, %v", result, err)
		}
	})

	t.Run("media type mismatch is still detected after parsing", func(t *testing.T) {
		f := newRegistryFixture()
		body := mustJSON(t, manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configBlob(t, f, "linux", "amd64"), Layers: []manifest.Descriptor{}})
		f.routes[latest] = body
		f.types[latest] = manifest.MediaTypeOCIImageIndex
		f.digests[latest] = digestFor(t, body)
		_, err := Scan(context.Background(), f.request(t, ""))
		integrityErr, ok := manifest.AsIntegrityError(err)
		if !ok || integrityErr.Kind != manifest.IntegrityMediaTypeMismatch {
			t.Fatalf("Scan() error = %v, want %s", err, manifest.IntegrityMediaTypeMismatch)
		}
	})
}

type tarEntry struct {
	name string
	body string
}

func gzipLayer(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name,
			Mode: 0600,
			Size: int64(len(entry.body)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader() error = %v", err)
		}
		if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tarWriter.Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzipWriter.Close() error = %v", err)
	}
	return buffer.Bytes()
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type contextReadCloser struct {
	ctx context.Context
}

func (r *contextReadCloser) Read(_ []byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func (r *contextReadCloser) Close() error {
	return nil
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func digestFor(t *testing.T, body []byte) string {
	t.Helper()
	digest, err := manifest.DigestBytes("sha256", body)
	if err != nil {
		t.Fatalf("manifest.DigestBytes() error = %v", err)
	}
	return digest
}

func descriptorFor(t *testing.T, mediaType string, body []byte) manifest.Descriptor {
	t.Helper()
	return manifest.Descriptor{
		MediaType: mediaType,
		Digest:    digestFor(t, body),
		Size:      int64(len(body)),
	}
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
		StatusCode:    statusCode,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}
