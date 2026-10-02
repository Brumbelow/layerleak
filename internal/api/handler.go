package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/jobs"
	"github.com/brumbelow/layerleak/v3/internal/limits"
	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/registry"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
	"github.com/brumbelow/layerleak/v3/internal/storage"
	"github.com/brumbelow/layerleak/v3/internal/version"
)

const (
	defaultPageLimit          = 50
	maxPageLimit              = 200
	defaultMaxRequestBytes    = int64(16 * (1 << 10))
	defaultScanTimeout        = 30 * time.Minute
	defaultMaxConcurrentScans = 1
	defaultQueryTimeout       = 10 * time.Second
	defaultReadinessTimeout   = 2 * time.Second
	defaultResponseTimeout    = 30 * time.Second
	defaultReadinessCacheTTL  = 5 * time.Second
)

type scanExecutor interface {
	ScanAndSave(rctx context.Context, request scanservice.Request) (scanservice.Outcome, error)
}

// Handler is the JSON API. It implements http.Handler through the middleware
// that wraps its mux, and tracks whether the server is draining.
type Handler struct {
	scanner   scanExecutor
	store     storage.ReadStore
	options   HandlerOptions
	scanSlots chan struct{}
	requestID func() string
	logger    *slog.Logger
	draining  atomic.Bool
	serve     http.Handler
	auth      *bearerAuth
	metrics   *metrics

	// readiness caches the last store check for ReadinessCacheTTL. The mutex
	// also serialises probes so one slow check is not run by every prober.
	readiness struct {
		sync.Mutex
		checkedAt time.Time
		err       error
		cached    bool
	}
}

type HandlerOptions struct {
	MaxRequestBytes    int64
	ScanTimeout        time.Duration
	MaxConcurrentScans int
	QueryTimeout       time.Duration
	ReadinessTimeout   time.Duration
	ResponseTimeout    time.Duration
	RequestID          func() string
	// ReadinessCacheTTL is how long a /readyz result is reused before the
	// store's schema-contract validation runs again. Zero disables the cache
	// and a negative value selects the 5 s default.
	ReadinessCacheTTL time.Duration
	// Logger receives request and lifecycle logs. Nil uses slog.Default().
	Logger *slog.Logger
	// BearerTokenDigests enables bearer-token authentication for every
	// /api/ path: each entry is the SHA-256 digest of an accepted token.
	// Empty keeps the API open. A digest of the wrong length is a
	// programming error and panics at construction.
	BearerTokenDigests [][]byte
}

const shuttingDownMessage = "the API is shutting down; retry against another instance"

type readinessChecker interface {
	Ready(context.Context) error
}

// healthResponse is the body of /health, /livez and a ready /readyz. Version
// is the build version so operators can tell which build answers.
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	// LimitKind and Limit accompany scan_limit_exceeded only.
	LimitKind string `json:"limit_kind,omitempty"`
	Limit     int64  `json:"limit,omitempty"`
}

type scanRequest struct {
	Reference string `json:"reference"`
	Platform  string `json:"platform,omitempty"`
	AllTags   bool   `json:"all_tags,omitempty"`
}

type scanResponse struct {
	ScanRunID int64           `json:"scan_run_id,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *errorResponse  `json:"error,omitempty"`
}

// List responses carry next_cursor: an opaque keyset position for the page
// after this one whenever the page was full, "" when the listing is known to
// be exhausted. It is additive beside limit and offset.
type repositoriesResponse struct {
	Repositories []repositoryItem `json:"repositories"`
	Limit        int              `json:"limit"`
	Offset       int              `json:"offset"`
	NextCursor   string           `json:"next_cursor"`
}

type repositoryScansResponse struct {
	Registry   string            `json:"registry"`
	Repository string            `json:"repository"`
	Scans      []scanSummaryItem `json:"scans"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
	NextCursor string            `json:"next_cursor"`
}

type repositoryItem struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	FirstSeen  string `json:"first_seen_at"`
	LastSeen   string `json:"last_seen_at"`
}

type repositoryFindingsResponse struct {
	Registry    string               `json:"registry"`
	Repository  string               `json:"repository"`
	Findings    []findingSummaryItem `json:"findings"`
	Disposition string               `json:"disposition"`
	Limit       int                  `json:"limit"`
	Offset      int                  `json:"offset"`
	NextCursor  string               `json:"next_cursor"`
}

type findingSummaryItem struct {
	ID                        int64    `json:"id"`
	ManifestDigest            string   `json:"manifest_digest"`
	Fingerprint               string   `json:"fingerprint"`
	RedactedValue             string   `json:"redacted_value"`
	FirstSeen                 string   `json:"first_seen_at"`
	LastSeen                  string   `json:"last_seen_at"`
	OccurrenceCount           int      `json:"occurrence_count"`
	ActionableOccurrenceCount int      `json:"actionable_occurrence_count"`
	SuppressedOccurrenceCount int      `json:"suppressed_occurrence_count"`
	Detectors                 []string `json:"detectors"`
}

type findingDetailResponse struct {
	Finding findingDetailItem `json:"finding"`
}

type scanSummaryItem struct {
	ID                           int64  `json:"id"`
	RequestedReference           string `json:"requested_reference"`
	ResolvedReference            string `json:"resolved_reference,omitempty"`
	RequestedDigest              string `json:"requested_digest,omitempty"`
	Mode                         string `json:"mode"`
	Status                       string `json:"status"`
	ErrorMessage                 string `json:"error_message,omitempty"`
	ScannedAt                    string `json:"scanned_at"`
	TagsEnumerated               int    `json:"tags_enumerated"`
	TagsResolved                 int    `json:"tags_resolved"`
	TagsFailed                   int    `json:"tags_failed"`
	TargetCount                  int    `json:"target_count"`
	CompletedTargetCount         int    `json:"completed_target_count"`
	FailedTargetCount            int    `json:"failed_target_count"`
	PartialTargetCount           int    `json:"partial_target_count"`
	ManifestCount                int    `json:"manifest_count"`
	CompletedManifestCount       int    `json:"completed_manifest_count"`
	FailedManifestCount          int    `json:"failed_manifest_count"`
	TotalFindings                int    `json:"total_findings"`
	UniqueFingerprints           int    `json:"unique_fingerprints"`
	SuppressedFindingsCount      int    `json:"suppressed_findings_count"`
	SuppressedUniqueFingerprints int    `json:"suppressed_unique_fingerprints"`
}

type scanDetailResponse struct {
	Scan scanDetailItem `json:"scan"`
}

type scanDetailItem struct {
	scanSummaryItem
	Registry   string          `json:"registry"`
	Repository string          `json:"repository"`
	Result     json.RawMessage `json:"result"`
}

type findingDetailItem struct {
	findingSummaryItem
	Occurrences []findingOccurrenceItem `json:"occurrences"`
}

type findingOccurrenceItem struct {
	DetectorName        string            `json:"detector_name"`
	Confidence          string            `json:"confidence"`
	Disposition         string            `json:"disposition"`
	DispositionReason   string            `json:"disposition_reason,omitempty"`
	SourceType          string            `json:"source_type"`
	Platform            manifest.Platform `json:"platform,omitempty"`
	FilePath            string            `json:"file_path,omitempty"`
	LayerDigest         string            `json:"layer_digest,omitempty"`
	Key                 string            `json:"key,omitempty"`
	LineNumber          int               `json:"line_number,omitempty"`
	ContextSnippet      string            `json:"context_snippet"`
	SourceLocation      string            `json:"source_location"`
	MatchStart          int               `json:"match_start"`
	MatchEnd            int               `json:"match_end"`
	PresentInFinalImage bool              `json:"present_in_final_image"`
	FirstSeen           string            `json:"first_seen_at"`
	LastSeen            string            `json:"last_seen_at"`
}

// NewHandler returns the JSON HTTP API mux. The scanner runs synchronous scans for
// POST /api/v1/scans; the store backs all read endpoints. Both must be non-nil.
func NewHandler(scanner scanExecutor, store storage.ReadStore) http.Handler {
	return NewHandlerWithOptions(scanner, store, HandlerOptions{})
}

// NewHandlerWithOptions returns the JSON HTTP API with explicit resource and
// deadline limits. Zero-valued options use the stable API defaults.
func NewHandlerWithOptions(scanner scanExecutor, store storage.ReadStore, options HandlerOptions) http.Handler {
	return newHandler(scanner, store, options)
}

func newHandler(scanner scanExecutor, store storage.ReadStore, options HandlerOptions) *Handler {
	options = options.withDefaults()
	auth, err := newBearerAuth(options.BearerTokenDigests)
	if err != nil {
		panic("api: " + err.Error())
	}
	handler := &Handler{
		scanner:   scanner,
		store:     store,
		options:   options,
		scanSlots: make(chan struct{}, options.MaxConcurrentScans),
		requestID: options.RequestID,
		logger:    options.Logger,
		auth:      auth,
		metrics:   newMetrics(version.Effective(), time.Now()),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.handleHealth)
	mux.HandleFunc("GET /livez", handler.handleHealth)
	mux.HandleFunc("GET /readyz", handler.handleReady)
	mux.HandleFunc("POST /api/v1/scans", handler.handleScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", handler.handleGetScan)
	mux.HandleFunc("GET /api/v1/repositories", handler.handleListRepositories)
	mux.HandleFunc("GET /api/v1/repositories/", handler.handleRepositorySubtree)
	mux.HandleFunc("GET /api/v1/findings/{id}", handler.handleGetFinding)
	mux.HandleFunc("/health", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/livez", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/readyz", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/api/v1/scans", handler.methodNotAllowed(http.MethodPost))
	mux.HandleFunc("/api/v1/scans/{id}", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/api/v1/repositories", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/api/v1/repositories/", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/api/v1/findings/{id}", handler.methodNotAllowed(http.MethodGet))
	mux.HandleFunc("/", handler.handleNotFound)
	handler.serve = handler.middleware(mux)
	return handler
}

// ServeHTTP serves the API through its middleware and mux.
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.serve.ServeHTTP(writer, request)
}

// startDraining marks the server as shutting down: /readyz reports 503
// not_ready, new scans are refused with 503 server_shutting_down, and
// requests whose contexts the drain cancels report the same code.
func (h *Handler) startDraining() {
	h.draining.Store(true)
}

func (h *Handler) isDraining() bool {
	return h.draining.Load()
}

func (options HandlerOptions) withDefaults() HandlerOptions {
	if options.MaxRequestBytes <= 0 {
		options.MaxRequestBytes = defaultMaxRequestBytes
	}
	if options.ScanTimeout <= 0 {
		options.ScanTimeout = defaultScanTimeout
	}
	if options.MaxConcurrentScans <= 0 {
		options.MaxConcurrentScans = defaultMaxConcurrentScans
	}
	if options.QueryTimeout <= 0 {
		options.QueryTimeout = defaultQueryTimeout
	}
	if options.ReadinessTimeout <= 0 {
		options.ReadinessTimeout = defaultReadinessTimeout
	}
	if options.ResponseTimeout <= 0 {
		options.ResponseTimeout = defaultResponseTimeout
	}
	if options.ReadinessCacheTTL < 0 {
		options.ReadinessCacheTTL = defaultReadinessCacheTTL
	}
	if options.RequestID == nil {
		options.RequestID = newRequestID
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return options
}

func (h *Handler) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, healthResponse{Status: "ok", Version: version.Effective()})
}

func (h *Handler) handleReady(writer http.ResponseWriter, _ *http.Request) {
	if h.isDraining() {
		writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "the API is draining before shutdown")
		return
	}
	checker, ok := h.store.(readinessChecker)
	if !ok || checker == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "database readiness check is not configured")
		return
	}
	if err := h.checkReadiness(checker); err != nil {
		h.logger.Warn("api readiness check failed", "error_type", fmt.Sprintf("%T", err), "request_id", requestIDFromWriter(writer))
		writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "database is not ready")
		return
	}
	writeJSON(writer, http.StatusOK, healthResponse{Status: "ready", Version: version.Effective()})
}

// checkReadiness runs the store's readiness check, reusing the previous
// result while it is younger than ReadinessCacheTTL. The check runs under
// its own bounded context rather than the prober's so a probe that hangs up
// cannot poison the shared result.
func (h *Handler) checkReadiness(checker readinessChecker) error {
	h.readiness.Lock()
	defer h.readiness.Unlock()
	ttl := h.options.ReadinessCacheTTL
	if ttl > 0 && h.readiness.cached && time.Since(h.readiness.checkedAt) < ttl {
		return h.readiness.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.options.ReadinessTimeout)
	defer cancel()
	err := checker.Ready(ctx)
	h.readiness.err = err
	h.readiness.checkedAt = time.Now()
	h.readiness.cached = ttl > 0
	return err
}

func (h *Handler) handleScan(writer http.ResponseWriter, request *http.Request) {
	if h.scanner == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "scan service is not configured")
		return
	}
	if h.isDraining() {
		writeAPIError(writer, http.StatusServiceUnavailable, "server_shutting_down", shuttingDownMessage)
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type"), request.ContentLength) {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	var body scanRequest
	request.Body = http.MaxBytesReader(writer, request.Body, h.options.MaxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", fmt.Sprintf("request body must not exceed %d bytes", h.options.MaxRequestBytes))
			return
		}
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", invalidBodyMessage(err))
		return
	}
	if err := requireSingleJSONValue(decoder); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "request_too_large", fmt.Sprintf("request body must not exceed %d bytes", h.options.MaxRequestBytes))
			return
		}
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", singleJSONObjectMessage)
		return
	}

	reference, err := manifest.ParseReference(body.Reference)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", invalidReferenceErrorMessage(body.Reference, err))
		return
	}
	if body.AllTags && !reference.IsRepositoryOnly() {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "all_tags requires a bare repository reference")
		return
	}
	platform := strings.TrimSpace(body.Platform)
	if platform != "" {
		if _, err := manifest.ParsePlatformSelector(platform); err != nil {
			writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	select {
	case h.scanSlots <- struct{}{}:
		defer func() { <-h.scanSlots }()
		h.metrics.scanStarted()
		defer h.metrics.scanFinished()
	default:
		writer.Header().Set("Retry-After", "5")
		writeAPIError(writer, http.StatusTooManyRequests, "scan_capacity_exceeded", "the maximum number of concurrent scans is already running")
		return
	}

	scanCtx, cancel := context.WithTimeout(request.Context(), h.options.ScanTimeout)
	defer cancel()
	outcome, err := h.scanner.ScanAndSave(scanCtx, scanservice.Request{
		Reference: reference,
		Platform:  platform,
		AllTags:   body.AllTags,
		Logger:    slog.Default(),
	})
	h.metrics.observeScan(scanOutcomeLabel(outcome.Result.Status, err))
	resultJSON, marshalErr := marshalScanResult(outcome.Result)
	if marshalErr != nil {
		slog.Error("encode scan result", "error_type", fmt.Sprintf("%T", marshalErr), "request_id", requestIDFromWriter(writer))
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "scan result could not be encoded")
		return
	}
	if err != nil {
		failure := classifyScanError(scanCtx, request.Context(), err, h.isDraining())
		slog.Warn("api scan failed", "error_type", fmt.Sprintf("%T", err), "error_code", failure.code, "status", failure.status, "request_id", requestIDFromWriter(writer))
		response := scanResponse{
			ScanRunID: outcome.ScanRunID,
			Error:     newErrorResponse(writer, failure.code, failure.message),
		}
		response.Error.LimitKind = failure.limitKind
		response.Error.Limit = failure.limit
		if hasResult(outcome.Result) {
			response.Result = resultJSON
		}
		if failure.retryAfter != "" {
			writer.Header().Set("Retry-After", failure.retryAfter)
		}
		writeJSON(writer, failure.status, response)
		return
	}

	writeJSON(writer, http.StatusOK, scanResponse{
		ScanRunID: outcome.ScanRunID,
		Result:    resultJSON,
	})
}

func (h *Handler) handleListRepositories(writer http.ResponseWriter, request *http.Request) {
	if h.store == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "read store is not configured")
		return
	}

	limit, offset, err := parsePagination(request.URL.Query())
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := parseCursorParam(request.URL.Query(), cursorKindRepository, offset)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositories(ctx, limit, offset, repositoryCursorFrom(cursor))
	if err != nil {
		h.writeStorageError(writer, "list repositories", err)
		return
	}

	response := repositoriesResponse{
		Repositories: make([]repositoryItem, 0, len(items)),
		Limit:        limit,
		Offset:       offset,
		NextCursor:   nextRepositoryCursor(items, limit),
	}
	for _, item := range items {
		response.Repositories = append(response.Repositories, repositoryItem{
			Registry:   item.Registry,
			Repository: item.Repository,
			FirstSeen:  item.FirstSeenAt.UTC().Format(time.RFC3339),
			LastSeen:   item.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) handleRepositorySubtree(writer http.ResponseWriter, request *http.Request) {
	if h.store == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "read store is not configured")
		return
	}

	switch {
	case strings.HasSuffix(request.URL.Path, "/findings"):
		h.handleListRepositoryFindings(writer, request)
	case strings.HasSuffix(request.URL.Path, "/scans"):
		h.handleListRepositoryScans(writer, request)
	default:
		h.handleNotFound(writer, request)
	}
}

func (h *Handler) handleListRepositoryScans(writer http.ResponseWriter, request *http.Request) {
	repository, ok, err := repositoryPathValue(request.URL.Path, "/scans")
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !ok {
		h.handleNotFound(writer, request)
		return
	}

	limit, offset, err := parsePagination(request.URL.Query())
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	registry, err := parseRegistryFilter(request.URL.Query().Get("registry"))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := parseCursorParam(request.URL.Query(), cursorKindScan, offset)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositoryScans(ctx, registry, repository, limit, offset, scanRunCursorFrom(cursor))
	if err != nil {
		h.writeStorageError(writer, "list repository scans", err)
		return
	}

	response := repositoryScansResponse{
		Registry:   registry,
		Repository: repository,
		Scans:      make([]scanSummaryItem, 0, len(items)),
		Limit:      limit,
		Offset:     offset,
		NextCursor: nextScanRunCursor(items, limit),
	}
	for _, item := range items {
		response.Scans = append(response.Scans, mapScanRunSummary(item))
	}

	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) handleListRepositoryFindings(writer http.ResponseWriter, request *http.Request) {
	repository, ok, err := repositoryPathValue(request.URL.Path, "/findings")
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !ok {
		h.handleNotFound(writer, request)
		return
	}

	disposition, err := parseDispositionFilter(request.URL.Query().Get("disposition"))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	limit, offset, err := parsePagination(request.URL.Query())
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	registry, err := parseRegistryFilter(request.URL.Query().Get("registry"))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := parseCursorParam(request.URL.Query(), cursorKindFinding, offset)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositoryFindings(ctx, registry, repository, disposition, limit, offset, findingCursorFrom(cursor))
	if err != nil {
		h.writeStorageError(writer, "list repository findings", err)
		return
	}

	response := repositoryFindingsResponse{
		Registry:    registry,
		Repository:  repository,
		Findings:    make([]findingSummaryItem, 0, len(items)),
		Disposition: string(disposition),
		Limit:       limit,
		Offset:      offset,
		NextCursor:  nextFindingCursor(items, limit),
	}
	for _, item := range items {
		response.Findings = append(response.Findings, mapFindingSummary(item))
	}

	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) handleGetScan(writer http.ResponseWriter, request *http.Request) {
	if h.store == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "read store is not configured")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(request.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "scan run id must be a positive integer")
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	item, err := h.store.GetScanRun(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(writer, http.StatusNotFound, "not_found", "scan run not found")
			return
		}
		h.writeStorageError(writer, "get scan run", err)
		return
	}
	resultJSON, err := sanitizeResultJSON(item.ResultJSON)
	if err != nil {
		slog.Error("decode stored scan result", "error_type", fmt.Sprintf("%T", err), "scan_run_id", id, "request_id", requestIDFromWriter(writer))
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "stored scan result is invalid")
		return
	}

	writeJSON(writer, http.StatusOK, scanDetailResponse{
		Scan: scanDetailItem{
			scanSummaryItem: mapScanRunSummary(item.ScanRunSummary),
			Registry:        item.Registry,
			Repository:      item.Repository,
			Result:          resultJSON,
		},
	})
}

func (h *Handler) handleGetFinding(writer http.ResponseWriter, request *http.Request) {
	if h.store == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "read store is not configured")
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(request.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "finding id must be a positive integer")
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	item, err := h.store.GetFinding(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(writer, http.StatusNotFound, "not_found", "finding not found")
			return
		}
		h.writeStorageError(writer, "get finding", err)
		return
	}

	response := findingDetailResponse{
		Finding: findingDetailItem{
			findingSummaryItem: mapFindingSummary(item.FindingSummary),
			Occurrences:        make([]findingOccurrenceItem, 0, len(item.Occurrences)),
		},
	}
	for _, occurrence := range item.Occurrences {
		response.Finding.Occurrences = append(response.Finding.Occurrences, findingOccurrenceItem{
			DetectorName:        occurrence.DetectorName,
			Confidence:          occurrence.Confidence,
			Disposition:         string(occurrence.Disposition),
			DispositionReason:   string(occurrence.DispositionReason),
			SourceType:          string(occurrence.SourceType),
			Platform:            occurrence.Platform,
			FilePath:            occurrence.FilePath,
			LayerDigest:         occurrence.LayerDigest,
			Key:                 occurrence.Key,
			LineNumber:          occurrence.LineNumber,
			ContextSnippet:      occurrence.ContextSnippet,
			SourceLocation:      occurrence.SourceLocation,
			MatchStart:          occurrence.MatchStart,
			MatchEnd:            occurrence.MatchEnd,
			PresentInFinalImage: occurrence.PresentInFinalImage,
			FirstSeen:           occurrence.FirstSeenAt.UTC().Format(time.RFC3339),
			LastSeen:            occurrence.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(writer, http.StatusOK, response)
}

// scanOutcomeLabel is the metrics outcome of one scan: the result's own status
// when the scanner produced one, otherwise failed on error and completed on
// success. A completed result that could not be stored still counts as a
// completed scan; the storage_unavailable code is counted separately.
func scanOutcomeLabel(status jobs.ResultStatus, err error) string {
	switch status {
	case jobs.ResultStatusCompleted, jobs.ResultStatusPartial, jobs.ResultStatusFailed:
		return string(status)
	}
	if err != nil {
		return string(jobs.ResultStatusFailed)
	}
	return string(jobs.ResultStatusCompleted)
}

func mapScanRunSummary(item storage.ScanRunSummary) scanSummaryItem {
	errorMessage := ""
	if strings.TrimSpace(item.ErrorMessage) != "" {
		errorMessage = "scan did not complete successfully"
	}
	return scanSummaryItem{
		ID:                           item.ID,
		RequestedReference:           item.RequestedReference,
		ResolvedReference:            item.ResolvedReference,
		RequestedDigest:              item.RequestedDigest,
		Mode:                         item.Mode,
		Status:                       string(item.Status),
		ErrorMessage:                 errorMessage,
		ScannedAt:                    item.ScannedAt.UTC().Format(time.RFC3339),
		TagsEnumerated:               item.TagsEnumerated,
		TagsResolved:                 item.TagsResolved,
		TagsFailed:                   item.TagsFailed,
		TargetCount:                  item.TargetCount,
		CompletedTargetCount:         item.CompletedTargetCount,
		FailedTargetCount:            item.FailedTargetCount,
		PartialTargetCount:           item.PartialTargetCount,
		ManifestCount:                item.ManifestCount,
		CompletedManifestCount:       item.CompletedManifestCount,
		FailedManifestCount:          item.FailedManifestCount,
		TotalFindings:                item.TotalFindings,
		UniqueFingerprints:           item.UniqueFingerprints,
		SuppressedFindingsCount:      item.SuppressedFindingsCount,
		SuppressedUniqueFingerprints: item.SuppressedUniqueFingerprints,
	}
}

func mapFindingSummary(item storage.FindingSummary) findingSummaryItem {
	return findingSummaryItem{
		ID:                        item.ID,
		ManifestDigest:            item.ManifestDigest,
		Fingerprint:               item.Fingerprint,
		RedactedValue:             item.RedactedValue,
		FirstSeen:                 item.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeen:                  item.LastSeenAt.UTC().Format(time.RFC3339),
		OccurrenceCount:           item.OccurrenceCount,
		ActionableOccurrenceCount: item.ActionableOccurrenceCount,
		SuppressedOccurrenceCount: item.SuppressedOccurrenceCount,
		Detectors:                 append([]string{}, item.Detectors...),
	}
}

const (
	repositoriesPrefix      = "/api/v1/repositories/"
	maxRepositoryNameLength = 255
)

// repositoryNamePattern is the OCI distribution <name> grammar: lowercase
// path components joined by single separators (. _ __ or one or more -) and
// slashes. Registry hosts are never part of the path.
var repositoryNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// repositoryPathValue extracts the repository from a subtree path whose final
// segment is suffix, for example "/scans". requestPath is request.URL.Path,
// which net/url has already percent-decoded once; it is not decoded again, so
// "%252F" stays "%2F" and fails validation. ok is false when no repository
// segment precedes the suffix (a 404); err reports a name outside the
// distribution grammar (a 400).
func repositoryPathValue(requestPath, suffix string) (string, bool, error) {
	rest, hasPrefix := strings.CutPrefix(requestPath, repositoriesPrefix)
	if !hasPrefix {
		return "", false, nil
	}
	repository, hasSuffix := strings.CutSuffix(rest, suffix)
	if !hasSuffix || repository == "" {
		return "", false, nil
	}
	if err := validateRepositoryName(repository); err != nil {
		return "", false, err
	}
	return repository, true, nil
}

func validateRepositoryName(name string) error {
	if len(name) > maxRepositoryNameLength || !repositoryNamePattern.MatchString(name) {
		return fmt.Errorf("repository must be a lowercase OCI repository path such as library/alpine")
	}
	return nil
}

// isCleanPath reports whether requestPath is already in the canonical form
// http.ServeMux would redirect to. Unclean paths (repeated slashes, dot
// segments) are answered with the JSON 404 before the mux sees them, so the
// API never emits a text/html redirect.
func isCleanPath(requestPath string) bool {
	if requestPath == "" || requestPath[0] != '/' {
		return false
	}
	// Rooting the argument explicitly keeps Clean from ever seeing a
	// relative path; requestPath already starts with "/", so this is the same
	// value and only the comparison below decides.
	cleaned := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	if strings.HasSuffix(requestPath, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned == requestPath
}

func parsePagination(values url.Values) (int, int, error) {
	limit := defaultPageLimit
	offset := 0

	if rawLimit := strings.TrimSpace(values.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil {
			return 0, 0, fmt.Errorf("limit must be an integer")
		}
		if parsed <= 0 {
			return 0, 0, fmt.Errorf("limit must be greater than zero")
		}
		if parsed > maxPageLimit {
			parsed = maxPageLimit
		}
		limit = parsed
	}

	if rawOffset := strings.TrimSpace(values.Get("offset")); rawOffset != "" {
		parsed, err := strconv.Atoi(rawOffset)
		if err != nil {
			return 0, 0, fmt.Errorf("offset must be an integer")
		}
		if parsed < 0 {
			return 0, 0, fmt.Errorf("offset must be greater than or equal to zero")
		}
		offset = parsed
	}

	return limit, offset, nil
}

var errInvalidRegistryFilter = errors.New("registry must be a hostname or IP address, optionally with a port")

// parseRegistryFilter validates the ?registry= query as host[:port] and
// returns the normalised value the store filters on: trimmed, lowercased,
// Docker Hub aliases folded to docker.io, and docker.io when empty. The
// returned value is echoed in the response.
func parseRegistryFilter(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "docker.io", "index.docker.io", "registry-1.docker.io":
		return manifest.DockerHubRegistry, nil
	}
	if err := validateRegistryHost(value); err != nil {
		return "", err
	}
	return value, nil
}

// validateRegistryHost accepts a lowercase hostname, IPv4 literal or bracketed
// IPv6 literal, each optionally followed by :port, matching the registry
// grammar manifest.ParseReference applies to image references.
func validateRegistryHost(value string) error {
	host := value
	if strings.HasPrefix(value, "[") {
		bracketed, port, err := net.SplitHostPort(value)
		if err != nil || net.ParseIP(bracketed) == nil || !validRegistryPort(port) {
			return errInvalidRegistryFilter
		}
		return nil
	}
	if colon := strings.LastIndexByte(value, ':'); colon >= 0 {
		if strings.Count(value, ":") != 1 || !validRegistryPort(value[colon+1:]) {
			return errInvalidRegistryFilter
		}
		host = value[:colon]
	}
	if host == "" {
		return errInvalidRegistryFilter
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return errInvalidRegistryFilter
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errInvalidRegistryFilter
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errInvalidRegistryFilter
			}
		}
	}
	return nil
}

func validRegistryPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func parseDispositionFilter(value string) (storage.FindingDispositionFilter, error) {
	switch strings.TrimSpace(value) {
	case "":
		return storage.FindingDispositionActionable, nil
	case string(storage.FindingDispositionActionable):
		return storage.FindingDispositionActionable, nil
	case string(storage.FindingDispositionSuppressed):
		return storage.FindingDispositionSuppressed, nil
	case string(storage.FindingDispositionAll):
		return storage.FindingDispositionAll, nil
	default:
		return "", fmt.Errorf("disposition must be one of actionable, suppressed, or all")
	}
}

func invalidBodyMessage(err error) string {
	if errors.Is(err, io.EOF) {
		return "request body is required"
	}
	return "request body must be valid JSON"
}

// singleJSONObjectMessage is the fixed 400 message for any data after the
// request object, whether another JSON value or bytes the decoder rejects; the
// decoder's own text quotes request bytes and is never returned.
const singleJSONObjectMessage = "request body must contain a single JSON object"

// invalidReferenceMessage is the fixed 400 message for a reference the parser
// rejects. The parser's error text can quote the submitted reference and the
// upstream distribution grammar error, so it is never returned to a client.
const invalidReferenceMessage = "reference is not a valid image reference"

// invalidReferenceErrorMessage maps a ParseReference failure to a fixed
// message: a missing reference and a local source scheme keep their own fixed
// text, every other failure is invalidReferenceMessage.
func invalidReferenceErrorMessage(raw string, err error) string {
	switch {
	case raw == "":
		return "image reference is required"
	case errors.Is(err, manifest.ErrLocalSourceNotSupported):
		return manifest.ErrLocalSourceNotSupported.Error()
	default:
		return invalidReferenceMessage
	}
}

func requireSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New(singleJSONObjectMessage)
}

// scanFailure is the HTTP mapping of a failed POST /api/v1/scans. Messages are
// fixed strings: the underlying error chain carries registry hosts, redirect
// targets and reference strings that must never reach a client.
type scanFailure struct {
	status     int
	code       string
	message    string
	retryAfter string
	limitKind  string
	limit      int64
}

// registryRateLimitRetryAfter is the Retry-After hint for 503
// registry_rate_limited. The registry client has already retried with the
// upstream Retry-After before giving up, so a longer back-off is suggested.
const registryRateLimitRetryAfter = "60"

// classifyScanError maps a scan failure to a response. Only the API's own scan
// deadline (scanCtx) produces 504 and only an ended request context produces
// 408 (or 503 server_shutting_down when the drain cancelled it): a context
// error nested inside the scan (the registry client bounds each request with
// its own timeout) is an upstream failure and reports 502.
func classifyScanError(scanCtx, requestCtx context.Context, err error, draining bool) scanFailure {
	switch {
	case scanservice.IsSaveError(err):
		return scanFailure{status: http.StatusServiceUnavailable, code: "storage_unavailable", message: "the scan result could not be stored"}
	case requestCtx.Err() != nil && draining:
		return scanFailure{status: http.StatusServiceUnavailable, code: "server_shutting_down", message: shuttingDownMessage}
	case requestCtx.Err() != nil:
		return scanFailure{status: http.StatusRequestTimeout, code: "scan_canceled", message: "the request was canceled before the scan completed"}
	case errors.Is(scanCtx.Err(), context.DeadlineExceeded):
		return scanFailure{status: http.StatusGatewayTimeout, code: "scan_timeout", message: "the scan exceeded its configured deadline"}
	case jobs.IsIncomplete(err):
		var incomplete *jobs.IncompleteError
		if errors.As(err, &incomplete) && incomplete != nil {
			return scanFailure{status: http.StatusUnprocessableEntity, code: "scan_incomplete", message: fmt.Sprintf(
				"scan coverage is %s: %d manifest(s) completed, %d failed",
				incomplete.Status,
				incomplete.CompletedManifestCount,
				incomplete.FailedManifestCount,
			)}
		}
		return scanFailure{status: http.StatusUnprocessableEntity, code: "scan_incomplete", message: "the scan did not cover every selected manifest"}
	case limits.IsExceeded(err):
		return limitExceededFailure(err)
	case registry.IsNotFound(err):
		return scanFailure{status: http.StatusNotFound, code: "image_not_found", message: "the requested image was not found in the registry"}
	case registry.IsRateLimited(err):
		return scanFailure{status: http.StatusServiceUnavailable, code: "registry_rate_limited", message: "the registry rate limited the scan; retry later", retryAfter: registryRateLimitRetryAfter}
	case registry.IsUnauthorized(err):
		return scanFailure{status: http.StatusBadGateway, code: "registry_unauthorized", message: "the registry refused access to the requested image"}
	default:
		return scanFailure{status: http.StatusBadGateway, code: "scan_failed", message: "the registry scan could not be completed"}
	}
}

// limitExceededFailure builds the scan_limit_exceeded response from the
// typed limit alone. The wrapped chain names blobs, manifests and repositories
// and changes with internal wording, so it never reaches the client.
func limitExceededFailure(err error) scanFailure {
	failure := scanFailure{
		status:  http.StatusUnprocessableEntity,
		code:    "scan_limit_exceeded",
		message: "the scan exceeded a configured resource limit",
	}
	exceeded, ok := limits.AsExceeded(err)
	if !ok || exceeded == nil {
		return failure
	}
	failure.limitKind = string(exceeded.Kind)
	failure.limit = exceeded.Limit
	kind := strings.ReplaceAll(strings.TrimSpace(string(exceeded.Kind)), "_", " ")
	if kind == "" {
		kind = "resource"
	}
	failure.message = fmt.Sprintf("the scan exceeded the configured %s limit of %d", kind, exceeded.Limit)
	return failure
}

func hasResult(result jobs.Result) bool {
	return strings.TrimSpace(result.RequestedReference) != "" ||
		strings.TrimSpace(result.Repository) != "" ||
		strings.TrimSpace(result.ResolvedReference) != "" ||
		len(result.Targets) > 0 ||
		len(result.TagResults) > 0 ||
		len(result.Findings) > 0 ||
		len(result.SuppressedFindings) > 0
}

func writeAPIError(writer http.ResponseWriter, statusCode int, code, message string) {
	writeJSON(writer, statusCode, map[string]any{
		"error": newErrorResponse(writer, code, message),
	})
}

func writeJSON(writer http.ResponseWriter, statusCode int, payload any) {
	setResponseWriteDeadline(writer)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(statusCode)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		slog.Error("encode api response", "error_type", fmt.Sprintf("%T", err), "status", statusCode)
	}
}

type apiResponseWriter struct {
	http.ResponseWriter
	requestID    string
	writeTimeout time.Duration
	wroteHeader  bool
	status       int
	bytes        int64
	// errorCode is the code of the last error envelope written, so the
	// middleware can count scan failures by code without each return path
	// reporting itself.
	errorCode string
}

// statusCode is the status the client saw: 200 when the handler wrote a body
// without an explicit WriteHeader, or nothing at all.
func (w *apiResponseWriter) statusCode() int {
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.status
}

func (w *apiResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *apiResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(body)
	w.bytes += int64(written)
	return written, err
}

func (w *apiResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (h *Handler) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		requestID := validRequestID(request.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = h.requestID()
		}
		wrapped := &apiResponseWriter{
			ResponseWriter: writer,
			requestID:      requestID,
			writeTimeout:   h.options.ResponseTimeout,
		}
		wrapped.Header().Set("X-Request-ID", requestID)
		wrapped.Header().Set("Cache-Control", "no-store")
		wrapped.Header().Set("X-Content-Type-Options", "nosniff")

		defer func() {
			if recovered := recover(); recovered != nil {
				if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					// net/http's convention: abort the response silently.
					panic(recovered)
				}
				// The stack names frames, never values; the panic value itself may
				// carry request or upstream detail and is reported by type only.
				h.logger.Error("panic serving api request",
					"panic_type", fmt.Sprintf("%T", recovered),
					"stack", string(debug.Stack()),
					"request_id", requestID,
				)
				if !wrapped.wroteHeader {
					writeAPIError(wrapped, http.StatusInternalServerError, "internal_error", "an internal error occurred")
				}
			}
			h.logAccess(wrapped, request, started)
			h.observeRequest(wrapped, request, started)
		}()

		if h.isDraining() && request.Context().Err() != nil {
			// The drain cancelled the base context before this request ran.
			writeAPIError(wrapped, http.StatusServiceUnavailable, "server_shutting_down", shuttingDownMessage)
			return
		}
		if !isCleanPath(request.URL.Path) {
			h.handleNotFound(wrapped, request)
			return
		}
		if !h.authorize(wrapped, request, requestID) {
			return
		}
		next.ServeHTTP(wrapped, request)
	})
}

// logAccess records one Info line per request. It logs the matched route
// pattern (request.Pattern), never the path or query, because repository
// names and reference strings belong to the caller, not the log stream.
func (h *Handler) logAccess(wrapped *apiResponseWriter, request *http.Request, started time.Time) {
	h.logger.Info("api request",
		"method", request.Method,
		"route", request.Pattern,
		"status", wrapped.statusCode(),
		"bytes", wrapped.bytes,
		"duration_ms", float64(time.Since(started).Microseconds())/1000,
		"request_id", wrapped.requestID,
		"remote_addr", request.RemoteAddr,
	)
}

// scanRoutePattern is the mux pattern whose error envelopes are counted as
// scan errors by code.
const scanRoutePattern = "POST /api/v1/scans"

// observeRequest feeds the request counters and the duration histogram. The
// route label is the mux pattern (or "none"), never the path.
func (h *Handler) observeRequest(wrapped *apiResponseWriter, request *http.Request, started time.Time) {
	route := routeLabel(request.Pattern)
	h.metrics.observeRequest(route, wrapped.statusCode(), time.Since(started))
	if route == scanRoutePattern && wrapped.errorCode != "" {
		h.metrics.observeScanError(wrapped.errorCode)
	}
}

func (h *Handler) methodNotAllowed(allowed string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Allow", allowed)
		writeAPIError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed for this endpoint")
	}
}

func (h *Handler) handleNotFound(writer http.ResponseWriter, _ *http.Request) {
	writeAPIError(writer, http.StatusNotFound, "not_found", "endpoint not found")
}

func (h *Handler) writeStorageError(writer http.ResponseWriter, operation string, err error) {
	slog.Warn("api storage request failed", "operation", operation, "error_type", fmt.Sprintf("%T", err), "request_id", requestIDFromWriter(writer))
	writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "database request failed")
}

func newErrorResponse(writer http.ResponseWriter, code, message string) *errorResponse {
	if wrapped := apiWriterOf(writer); wrapped != nil {
		wrapped.errorCode = code
	}
	return &errorResponse{
		Code:      code,
		Message:   message,
		RequestID: requestIDFromWriter(writer),
	}
}

// apiWriterOf unwraps to the middleware's response writer, or nil when the
// handler is served without the middleware (direct unit tests).
func apiWriterOf(writer http.ResponseWriter) *apiResponseWriter {
	for {
		wrapped, ok := writer.(*apiResponseWriter)
		if !ok {
			return nil
		}
		if wrapped.requestID != "" {
			return wrapped
		}
		writer = wrapped.ResponseWriter
	}
}

func requestIDFromWriter(writer http.ResponseWriter) string {
	if wrapped := apiWriterOf(writer); wrapped != nil {
		return wrapped.requestID
	}
	return ""
}

func validRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return ""
	}
	// The allow-list above already excludes line breaks; removing them again
	// keeps that guarantee visible where the value reaches the access log.
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
}

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func isJSONContentType(value string, contentLength int64) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return contentLength == 0
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || (strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

func marshalScanResult(result jobs.Result) (json.RawMessage, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return sanitizeResultJSON(body)
}

func sanitizeResultJSON(body []byte) (json.RawMessage, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	if err := requireSingleJSONValue(decoder); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	sanitizeResultErrors(value)
	sanitized, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode scan result: %w", err)
	}
	return json.RawMessage(sanitized), nil
}

func sanitizeResultErrors(value any) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if (key == "error" || key == "error_message") && strings.TrimSpace(fmt.Sprint(child)) != "" {
				item[key] = "scan step failed"
				continue
			}
			if key == "message" {
				if code, ok := item["code"].(string); ok {
					item[key] = safeDiagnosticMessage(code)
					continue
				}
			}
			sanitizeResultErrors(child)
		}
	case []any:
		for _, child := range item {
			sanitizeResultErrors(child)
		}
	}
}

// diagnosticMessages is the fixed text the API returns for each diagnostic
// code with its own message; every other code returns "scan step failed".
// web/docs/openapi.yaml lists each value in the closed Diagnostic.message enum
// and names each code in its description; TestDiagnosticMessagesMatchOpenAPIEnum
// keeps the two in lockstep.
var diagnosticMessages = map[string]string{
	"files_skipped_oversize":         "one or more files exceeded the configured per-file scan limit",
	"max_findings_exceeded":          "the scan exceeded the configured findings limit",
	"max_raw_finding_bytes_exceeded": "the scan exceeded the configured raw finding byte limit",
	"raw_retention_truncated":        "raw secret retention stopped at the configured byte limit; detection continued without raw values",
	"platform_skipped":               "a platform manifest was skipped by the default linux-only platform policy",
	"manifest_skipped":               "an index entry that is not an image manifest was skipped",
	"manifest_unsupported":           "a selected manifest uses layers that cannot be scanned",
	"platform_not_found":             "the requested platform was not found in the image",
	"layer_trailing_data":            "a layer blob carried data after the end of its compressed stream",
	"unsafe_archive_entries_skipped": "layer entries with unsafe paths or links were skipped",
	"nested_archive_skipped":         "an archive stored in a layer was not expanded; its own file was still scanned",
}

func safeDiagnosticMessage(code string) string {
	if message, ok := diagnosticMessages[code]; ok {
		return message
	}
	return "scan step failed"
}

func setResponseWriteDeadline(writer http.ResponseWriter) {
	wrapped, ok := writer.(*apiResponseWriter)
	if !ok || wrapped.writeTimeout <= 0 {
		return
	}
	err := http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(wrapped.writeTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("set api response deadline", "error_type", fmt.Sprintf("%T", err), "request_id", wrapped.requestID)
	}
}
