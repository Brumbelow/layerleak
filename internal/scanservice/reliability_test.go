package scanservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
	"github.com/brumbelow/layerleak/internal/storage"
)

func TestScanAndSaveRetainsScanErrorWhenStorageFails(t *testing.T) {
	saveErr := errors.New("synthetic database failure")
	service := New(config.Config{RegistryBaseURL: "https://registry.test", MaxFileBytes: 1 << 20}, &failingStore{err: saveErr})
	service.newRegistryClient = func(options registry.Options) *registry.Client {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return testResponse(http.StatusNotFound, "text/plain", []byte("missing"), nil), nil
		})}
		return registry.NewClient(options)
	}
	ref, _ := manifest.ParseReference("library/app:latest")
	outcome, err := service.ScanAndSave(context.Background(), Request{Reference: ref})
	if !IsSaveError(err) || !errors.Is(err, saveErr) {
		t.Fatalf("save error not retained: %v", err)
	}
	if outcome.ScanError == nil || !errors.Is(err, outcome.ScanError) {
		t.Fatalf("original incomplete scan error not retained: %v", err)
	}
	if outcome.Result.Status != jobs.ResultStatusFailed || outcome.ScanRunID != 0 {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestBeforeSaveProgressFailureDoesNotVetoPersistence(t *testing.T) {
	store := &recordingStore{}
	service := New(config.Config{RegistryBaseURL: "https://registry.test", MaxFileBytes: 1 << 20}, store)
	service.newRegistryClient = func(options registry.Options) *registry.Client {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return testResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		})}
		return registry.NewClient(options)
	}
	ref, _ := manifest.ParseReference("library/app:latest")
	outcome, err := service.ScanAndSave(context.Background(), Request{Reference: ref, BeforeSave: func(jobs.Result) error { return errors.New("broken progress stream") }})
	if outcome.ScanRunID != 1 || len(store.records) != 1 || IsSaveError(err) {
		t.Fatalf("progress vetoed saving: id=%d records=%d err=%v", outcome.ScanRunID, len(store.records), err)
	}
}

type failingStore struct{ err error }

func (s *failingStore) Name() string                                                { return "failing" }
func (s *failingStore) SaveScan(context.Context, storage.ScanRecord) (int64, error) { return 0, s.err }

func TestScanAndSaveSeparatesCoverageAndPersistenceOutcomes(t *testing.T) {
	for _, status := range []jobs.ResultStatus{jobs.ResultStatusCompleted, jobs.ResultStatusPartial, jobs.ResultStatusFailed} {
		for _, saveFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/save_fails=%v", status, saveFails), func(t *testing.T) {
				store := &outcomeStore{fail: saveFails}
				service := outcomeTestService(t, store, status)
				ref, _ := manifest.ParseReference("library/app:latest")
				outcome, err := service.ScanAndSave(context.Background(), Request{Reference: ref, BeforeSave: func(jobs.Result) error { return io.ErrClosedPipe }})
				assertStoredCoverage(t, outcome, store.records, status, err)
				assertSeparateOutcomeErrors(t, outcome, err, status, saveFails)
				assertPersistenceOutcome(t, outcome, err, saveFails)
			})
		}
	}
}

func assertStoredCoverage(t *testing.T, outcome Outcome, records []storage.ScanRecord, status jobs.ResultStatus, err error) {
	t.Helper()
	if outcome.Result.Status != status || len(records) != 1 || string(records[0].Status) != string(status) {
		t.Fatalf("coverage lost: outcome=%+v records=%+v err=%v", outcome, records, err)
	}
}

func assertSeparateOutcomeErrors(t *testing.T, outcome Outcome, err error, status jobs.ResultStatus, saveFails bool) {
	t.Helper()
	if (outcome.ScanError != nil) != (status != jobs.ResultStatusCompleted) || (outcome.SaveError != nil) != saveFails {
		t.Fatalf("errors not separate: scan=%v save=%v", outcome.ScanError, outcome.SaveError)
	}
	if outcome.ScanError != nil && !errors.Is(err, outcome.ScanError) {
		t.Fatalf("scan error lost: %v", err)
	}
	if outcome.ScanError == nil && outcome.SaveError == nil && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertPersistenceOutcome(t *testing.T, outcome Outcome, err error, saveFails bool) {
	t.Helper()
	if saveFails {
		if outcome.ScanRunID != 0 || !IsSaveError(err) || !errors.Is(err, outcome.SaveError) {
			t.Fatalf("save outcome=%+v err=%v", outcome, err)
		}
	} else if outcome.ScanRunID != 12 || IsSaveError(err) {
		t.Fatalf("save outcome=%+v err=%v", outcome, err)
	}
}

type outcomeStore struct {
	fail    bool
	records []storage.ScanRecord
}

func (s *outcomeStore) Name() string { return "recording" }
func (s *outcomeStore) SaveScan(_ context.Context, record storage.ScanRecord) (int64, error) {
	s.records = append(s.records, record)
	if s.fail {
		return 99, errors.New("synthetic storage detail")
	}
	return 12, nil
}

func outcomeTestService(t *testing.T, store storage.Store, status jobs.ResultStatus) *Service {
	t.Helper()
	configBody := []byte(`{"architecture":"amd64","os":"linux","config":{}}`)
	configDescriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageConfig, configBody)
	manifestBody := scanTestManifestBody(t, configDescriptor)
	descriptor := scanTestDescriptor(t, manifest.MediaTypeOCIImageManifest, manifestBody)
	descriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	missing := descriptor
	missing.Digest = "sha256:" + strings.Repeat("b", 64)
	missing.Platform.Architecture = "arm64"
	indexBody, err := json.Marshal(manifest.ImageIndex{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageIndex, Manifests: []manifest.Descriptor{descriptor, missing}})
	if err != nil {
		t.Fatal(err)
	}
	service := New(config.Config{RegistryBaseURL: "https://registry.test", MaxFileBytes: 1 << 20}, store)
	service.newRegistryClient = func(options registry.Options) *registry.Client {
		options.AllowPrivateHosts = true
		options.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if status == jobs.ResultStatusFailed {
				return testResponse(http.StatusNotFound, "text/plain", nil, nil), nil
			}
			switch request.URL.Path {
			case "/v2/library/app/manifests/latest":
				if status == jobs.ResultStatusPartial {
					return testResponse(http.StatusOK, manifest.MediaTypeOCIImageIndex, indexBody, nil), nil
				}
				return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, nil), nil
			case "/v2/library/app/manifests/" + descriptor.Digest:
				return testResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, manifestBody, nil), nil
			case "/v2/library/app/blobs/" + configDescriptor.Digest:
				return testResponse(http.StatusOK, manifest.MediaTypeOCIImageConfig, configBody, nil), nil
			default:
				return testResponse(http.StatusNotFound, "text/plain", nil, nil), nil
			}
		})}
		return registry.NewClient(options)
	}
	return service
}
