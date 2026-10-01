package scanservice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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
	Reference manifest.Reference
	Platform  string
	AllTags   bool
	// Credential is a username and password the caller vouches for: it belongs
	// to the registry of this scan and is bound to the host the client will
	// contact (the reference's registry, or the LAYERLEAK_REGISTRY_BASE_URL
	// override). The CLI sets it from its flags or from
	// ConfiguredCredential; the API never sets it, so a caller-named registry
	// can never obtain the operator's credential. Zero means none.
	Credential registry.Credential
	// ScannerVersion is reported in the result's scanner block; empty means
	// the build version of this binary.
	ScannerVersion string
	Logger         *slog.Logger
	Progress       jobs.ProgressFunc
	BeforeSave     BeforeSaveFunc
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
	registryClient, err := s.registryClient(request.Reference, request)
	if err != nil {
		configErr := fmt.Errorf("configure registry client: %w", err)
		return Outcome{ScanError: configErr}, wrapScanError(configErr)
	}
	result, scanErr := jobs.Scan(ctx, jobs.Request{
		Reference:          request.Reference,
		Platform:           request.Platform,
		Registry:           registryClient,
		Detectors:          s.detectors,
		Logger:             request.Logger,
		ScannerVersion:     request.ScannerVersion,
		Now:                s.now,
		MaxFileBytes:       s.config.MaxFileBytes,
		MaxLayerBytes:      s.config.MaxLayerBytes,
		MaxLayerEntries:    s.config.MaxLayerEntries,
		MaxConfigBytes:     s.config.MaxConfigBytes,
		MaxImageLayers:     s.config.MaxImageLayers,
		MaxImageManifests:  s.config.MaxImageManifests,
		MaxImageLayerBytes: s.config.MaxImageLayerBytes,
		MaxImageArtifacts:  s.config.MaxImageArtifacts,
		MaxRetainedBytes:   s.config.MaxRetainedBytes,

		MaxNestedArchiveBytes:   s.config.MaxNestedArchiveBytes,
		MaxNestedArchiveEntries: s.config.MaxNestedArchiveEntries,
		MaxLayerCacheBytes:      s.config.MaxLayerCacheBytes,

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

func (s *Service) registryClient(ref manifest.Reference, request Request) (*registry.Client, error) {
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
		Credentials:                 s.credentialSource(baseURL, request.Credential),
	}
	if s.newRegistryClient != nil {
		return s.newRegistryClient(options)
	}
	return registry.NewClient(options)
}

// ConfiguredCredential returns the LAYERLEAK_REGISTRY_USERNAME/PASSWORD pair
// as a credential for Request.Credential, or the zero Credential when the
// pair is not set. The CLI uses it to apply the configured pair to the
// registry of the reference it was given on the command line.
func ConfiguredCredential(cfg config.Config) registry.Credential {
	if cfg.RegistryUsername == "" && cfg.RegistryPassword == "" {
		return registry.Credential{}
	}
	return registry.Credential{Username: cfg.RegistryUsername, Password: string(cfg.RegistryPassword)}
}

// credentialSource builds the credential chain for one scan: a static
// credential bound to the registry host the client will contact, then the
// Docker config.json when one is configured. It returns nil, and the client
// stays anonymous, when neither applies.
//
// The static credential is the caller's Request.Credential when set.
// Otherwise the configured LAYERLEAK_REGISTRY_USERNAME/PASSWORD pair is used
// only when LAYERLEAK_REGISTRY_BASE_URL pins the host: in that case every scan
// of the process goes to the operator's registry, so the pair cannot leave it.
// Without the pin the host is whatever reference the caller submitted, and in
// server mode that caller is an unauthenticated API client whose registry can
// advertise an arbitrary token realm; binding the pair there would hand the
// operator's password to any host a caller names. Docker config entries are
// keyed by host and stay available either way.
func (s *Service) credentialSource(baseURL string, requested registry.Credential) registry.CredentialSource {
	sources := make([]registry.CredentialSource, 0, 2)
	credential := requested
	if credential.IsZero() && s.config.RegistryBaseURL != "" {
		credential = ConfiguredCredential(s.config)
	}
	if !credential.IsZero() {
		host := baseURL
		if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
		sources = append(sources, registry.StaticCredentials(host, credential.Username, credential.Password))
	}
	if s.config.DockerConfigPath != "" {
		sources = append(sources, registry.DockerConfigCredentials(s.config.DockerConfigPath))
	}
	if len(sources) == 0 {
		return nil
	}
	return registry.ChainCredentials(sources...)
}

func wrapScanError(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Phase: ErrorPhaseScan, Err: err}
}
