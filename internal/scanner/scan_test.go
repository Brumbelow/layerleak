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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/findings"
	"github.com/brumbelow/layerleak/internal/layers"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
				Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		Registry: registry.NewClient(registry.Options{
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
		if budget.rawBytes != 0 || budget.rawExceeded {
			t.Fatalf("raw budget = %d, exceeded = %t", budget.rawBytes, budget.rawExceeded)
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
		if budget.rawBytes != wantBytes || budget.rawExceeded {
			t.Fatalf("raw budget = %d, want %d, exceeded = %t", budget.rawBytes, wantBytes, budget.rawExceeded)
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
		if !budget.stopped() || !budget.rawExceeded || budget.rawBytes != 0 {
			t.Fatalf("raw budget = %d, stopped = %t, exceeded = %t", budget.rawBytes, budget.stopped(), budget.rawExceeded)
		}
		diagnostic := budget.diagnostic()
		if diagnostic.Code != "max_raw_finding_bytes_exceeded" || diagnostic.Limit != 1 || diagnostic.Observed <= diagnostic.Limit {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
		if later := budget.scan(detectors.Default(), input, scanInput); len(later) != 0 {
			t.Fatalf("len(later) = %d", len(later))
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
