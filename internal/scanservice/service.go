package scanservice

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/brumbelow/layerleak/internal/config"
	"github.com/brumbelow/layerleak/internal/detectors"
	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/registry"
	"github.com/brumbelow/layerleak/internal/storage"
)

type BeforeSaveFunc func(result jobs.Result) error

type Request struct {
	Reference  manifest.Reference
	Platform   string
	Logger     *slog.Logger
	Progress   jobs.ProgressFunc
	BeforeSave BeforeSaveFunc
}

type ErrorPhase string

const (
	ErrorPhaseScan ErrorPhase = "scan"
	ErrorPhaseSave ErrorPhase = "save"
)

type Error struct {
	Phase ErrorPhase
	Err   error
}

type Outcome struct {
	Result    jobs.Result
	ScanRunID int64
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func IsSaveError(err error) bool {
	var target *Error
	return errors.As(err, &target) && target.Phase == ErrorPhaseSave
}

type Service struct {
	config            config.Config
	store             storage.Store
	now               func() time.Time
	detectors         detectors.Set
	newRegistryClient func() *registry.Client
}

func New(cfg config.Config, store storage.Store) *Service {
	if store == nil {
		store = storage.NewNoopStore()
	}

	return &Service{
		config:    cfg,
		store:     store,
		now:       time.Now,
		detectors: detectors.Default(),
	}
}

func (s *Service) ScanAndSave(ctx context.Context, request Request) (Outcome, error) {
	result, scanErr := jobs.Scan(ctx, jobs.Request{
		Reference:            request.Reference,
		Platform:             request.Platform,
		Registry:             s.registryClient(),
		Detectors:            s.detectors,
		Logger:               request.Logger,
		MaxFileBytes:         s.config.MaxFileBytes,
		MaxLayerBytes:        s.config.MaxLayerBytes,
		MaxLayerEntries:      s.config.MaxLayerEntries,
		MaxConfigBytes:       s.config.MaxConfigBytes,
		TagPageSize:          s.config.TagPageSize,
		MaxRepositoryTags:    s.config.MaxRepositoryTags,
		MaxRepositoryTargets: s.config.MaxRepositoryTargets,
		Progress:             request.Progress,
	})
	outcome := Outcome{Result: result}

	if s.store == nil || s.store.Name() == "noop" {
		return outcome, wrapScanError(scanErr)
	}

	if request.BeforeSave != nil {
		if hookErr := request.BeforeSave(result); hookErr != nil {
			return outcome, &Error{Phase: ErrorPhaseSave, Err: hookErr}
		}
	}

	scannedAt := s.now().UTC()
	record, recordErr := BuildScanRecord(request.Reference, result, scannedAt, scanErr)
	if recordErr != nil {
		return outcome, &Error{Phase: ErrorPhaseSave, Err: recordErr}
	}
	scanRunID, storeErr := s.store.SaveScan(ctx, record)
	if storeErr != nil {
		return outcome, &Error{Phase: ErrorPhaseSave, Err: storeErr}
	}
	outcome.ScanRunID = scanRunID

	return outcome, wrapScanError(scanErr)
}

func (s *Service) registryClient() *registry.Client {
	if s.newRegistryClient != nil {
		return s.newRegistryClient()
	}

	return registry.NewClient(registry.Options{
		BaseURL:             s.config.RegistryBaseURL,
		AuthURL:             s.config.RegistryAuthURL,
		MaxTagResponseBytes: s.config.MaxTagResponseBytes,
		HTTPClient: &http.Client{
			Timeout: s.config.HTTPTimeout,
		},
		RequestAttempts:  s.config.RegistryRequestAttempts,
		MaxManifestBytes: s.config.MaxManifestBytes,
	})
}

func wrapScanError(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Phase: ErrorPhaseScan, Err: err}
}
