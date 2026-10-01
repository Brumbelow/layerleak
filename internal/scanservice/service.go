package scanservice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/detectors"
	"github.com/brumbelow/layerleak/v3/internal/findings"
	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

type BeforeSaveFunc func(result jobs.Result) error

type Request struct {
	Reference  manifest.Reference
	Platform   string
	AllTags    bool
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
	ScanError error
	SaveError error
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
	newRegistryClient func(registry.Options) (*registry.Client, error)
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
	if ctx == nil {
		ctx = context.Background()
	}
	registryClient, err := s.registryClient(request.Reference)
	if err != nil {
		configErr := fmt.Errorf("configure registry client: %w", err)
		return Outcome{ScanError: configErr}, wrapScanError(configErr)
	}
	result, scanErr := jobs.Scan(ctx, jobs.Request{
		Reference:            request.Reference,
		Platform:             request.Platform,
		Registry:             registryClient,
		Detectors:            s.detectors,
		Logger:               request.Logger,
		MaxFileBytes:         s.config.MaxFileBytes,
		MaxLayerBytes:        s.config.MaxLayerBytes,
		MaxLayerEntries:      s.config.MaxLayerEntries,
		MaxConfigBytes:       s.config.MaxConfigBytes,
		MaxImageLayers:       s.config.MaxImageLayers,
		MaxImageManifests:    s.config.MaxImageManifests,
		MaxImageLayerBytes:   s.config.MaxImageLayerBytes,
		MaxImageArtifacts:    s.config.MaxImageArtifacts,
		MaxRetainedBytes:     s.config.MaxRetainedBytes,
		MaxFindings:          s.config.MaxFindingsPerScan,
		RetainRawSecrets:     s.config.PersistRawSecrets,
		MaxRawFindingBytes:   s.config.MaxRawFindingBytes,
		ConfigTimeout:        s.config.HTTPTimeout,
		BlobTimeout:          s.config.BlobTimeout,
		TagPageSize:          s.config.TagPageSize,
		MaxRepositoryTags:    s.config.MaxRepositoryTags,
		MaxRepositoryTargets: s.config.MaxRepositoryTargets,
		AllTags:              request.AllTags,
		Progress:             request.Progress,
	})
	if !s.config.PersistRawSecrets {
		findings.StripRawSecrets(result.DetailedFindings)
		findings.StripRawSecrets(result.SuppressedDetailedFindings)
	}
	outcome := Outcome{Result: result, ScanError: scanErr}

	if s.store == nil || s.store.Name() == "noop" {
		return outcome, wrapScanError(scanErr)
	}
	// A scan that did not finish while its context ended was interrupted by
	// that cancellation and is not persisted. A scan that completed is
	// persisted even when the caller has since gone away (client disconnect or
	// scan deadline between completion and the write), so the work is not
	// silently discarded.
	if scanErr != nil && ctx.Err() != nil {
		return outcome, wrapScanError(scanErr)
	}

	if request.BeforeSave != nil {
		if hookErr := request.BeforeSave(result); hookErr != nil && request.Logger != nil {
			request.Logger.Debug("progress update failed")
		}
	}

	scannedAt := s.now().UTC()
	record, recordErr := BuildScanRecord(request.Reference, result, scannedAt, scanErr)
	if recordErr != nil {
		outcome.SaveError = recordErr
		return outcome, errors.Join(&Error{Phase: ErrorPhaseSave, Err: recordErr}, wrapScanError(scanErr))
	}
	saveCtx, cancelSave := context.WithTimeout(context.WithoutCancel(ctx), s.saveTimeout())
	defer cancelSave()
	scanRunID, storeErr := s.store.SaveScan(saveCtx, record)
	if storeErr != nil {
		outcome.SaveError = storeErr
		return outcome, errors.Join(&Error{Phase: ErrorPhaseSave, Err: storeErr}, wrapScanError(scanErr))
	}
	outcome.ScanRunID = scanRunID

	return outcome, wrapScanError(scanErr)
}

// saveTimeout bounds the persistence phase, which runs detached from the
// caller's context so a disconnect after the scan finished cannot discard it.
func (s *Service) saveTimeout() time.Duration {
	if s.config.DatabaseWriteTimeout > 0 {
		return s.config.DatabaseWriteTimeout
	}
	return storage.DefaultWriteTimeout
}

func (s *Service) registryClient(ref manifest.Reference) (*registry.Client, error) {
	baseURL := s.config.RegistryBaseURL
	if baseURL == "" {
		baseURL = registry.BaseURLForRegistry(ref.Registry)
	}

	options := registry.Options{
		BaseURL:                     baseURL,
		AuthURL:                     s.config.RegistryAuthURL,
		RequestTimeout:              s.config.HTTPTimeout,
		MaxTagResponseBytes:         s.config.MaxTagResponseBytes,
		MaxAuthResponseBytes:        s.config.MaxAuthResponseBytes,
		MaxRedirects:                s.config.RegistryMaxRedirects,
		AllowedPrivateRegistryHosts: s.config.AllowedPrivateRegistryHosts,
		AllowedPrivateAuthHosts:     s.config.AllowedPrivateAuthHosts,
		RequestAttempts:             s.config.RegistryRequestAttempts,
		MaxManifestBytes:            s.config.MaxManifestBytes,
	}
	if s.newRegistryClient != nil {
		return s.newRegistryClient(options)
	}
	return registry.NewClient(options)
}

func wrapScanError(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Phase: ErrorPhaseScan, Err: err}
}
