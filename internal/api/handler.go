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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
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
)

type scanExecutor interface {
	ScanAndSave(rctx context.Context, request scanservice.Request) (scanservice.Outcome, error)
}

type Handler struct {
	scanner   scanExecutor
	store     storage.ReadStore
	options   HandlerOptions
	scanSlots chan struct{}
	requestID func() string
}

type HandlerOptions struct {
	MaxRequestBytes    int64
	ScanTimeout        time.Duration
	MaxConcurrentScans int
	QueryTimeout       time.Duration
	ReadinessTimeout   time.Duration
	ResponseTimeout    time.Duration
	RequestID          func() string
}

type readinessChecker interface {
	Ready(context.Context) error
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
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

type repositoriesResponse struct {
	Repositories []repositoryItem `json:"repositories"`
	Limit        int              `json:"limit"`
	Offset       int              `json:"offset"`
}

type repositoryScansResponse struct {
	Repository string            `json:"repository"`
	Scans      []scanSummaryItem `json:"scans"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
}

type repositoryItem struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	FirstSeen  string `json:"first_seen_at"`
	LastSeen   string `json:"last_seen_at"`
}

type repositoryFindingsResponse struct {
	Repository  string               `json:"repository"`
	Findings    []findingSummaryItem `json:"findings"`
	Disposition string               `json:"disposition"`
	Limit       int                  `json:"limit"`
	Offset      int                  `json:"offset"`
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
	options = options.withDefaults()
	handler := &Handler{
		scanner:   scanner,
		store:     store,
		options:   options,
		scanSlots: make(chan struct{}, options.MaxConcurrentScans),
		requestID: options.RequestID,
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
	return handler.middleware(mux)
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
	if options.RequestID == nil {
		options.RequestID = newRequestID
	}
	return options
}

func (h *Handler) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleReady(writer http.ResponseWriter, request *http.Request) {
	checker, ok := h.store.(readinessChecker)
	if !ok || checker == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "database readiness check is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), h.options.ReadinessTimeout)
	defer cancel()
	if err := checker.Ready(ctx); err != nil {
		slog.Warn("api readiness check failed", "error_type", fmt.Sprintf("%T", err), "request_id", requestIDFromWriter(writer))
		writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "database is not ready")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) handleScan(writer http.ResponseWriter, request *http.Request) {
	if h.scanner == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "scan service is not configured")
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
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	reference, err := manifest.ParseReference(body.Reference)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
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
	resultJSON, marshalErr := marshalScanResult(outcome.Result)
	if marshalErr != nil {
		slog.Error("encode scan result", "error_type", fmt.Sprintf("%T", marshalErr), "request_id", requestIDFromWriter(writer))
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "scan result could not be encoded")
		return
	}
	if err != nil {
		statusCode, code, message := classifyScanError(err)
		slog.Warn("api scan failed", "error_type", fmt.Sprintf("%T", err), "error_code", code, "status", statusCode, "request_id", requestIDFromWriter(writer))
		response := scanResponse{
			ScanRunID: outcome.ScanRunID,
			Error:     newErrorResponse(writer, code, message),
		}
		if hasResult(outcome.Result) {
			response.Result = resultJSON
		}
		writeJSON(writer, statusCode, response)
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

	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositories(ctx, limit, offset)
	if err != nil {
		h.writeStorageError(writer, "list repositories", err)
		return
	}

	response := repositoriesResponse{
		Repositories: make([]repositoryItem, 0, len(items)),
		Limit:        limit,
		Offset:       offset,
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

	registry := request.URL.Query().Get("registry")
	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositoryScans(ctx, registry, repository, limit, offset)
	if err != nil {
		h.writeStorageError(writer, "list repository scans", err)
		return
	}

	response := repositoryScansResponse{
		Repository: repository,
		Scans:      make([]scanSummaryItem, 0, len(items)),
		Limit:      limit,
		Offset:     offset,
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

	registry := request.URL.Query().Get("registry")
	ctx, cancel := context.WithTimeout(request.Context(), h.options.QueryTimeout)
	defer cancel()
	items, err := h.store.ListRepositoryFindings(ctx, registry, repository, disposition, limit, offset)
	if err != nil {
		h.writeStorageError(writer, "list repository findings", err)
		return
	}

	response := repositoryFindingsResponse{
		Repository:  repository,
		Findings:    make([]findingSummaryItem, 0, len(items)),
		Disposition: string(disposition),
		Limit:       limit,
		Offset:      offset,
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

func repositoryPathValue(path, suffix string) (string, bool, error) {
	const prefix = "/api/v1/repositories/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false, nil
	}

	rawRepository := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	repository, err := url.PathUnescape(strings.Trim(rawRepository, "/"))
	if err != nil {
		return "", false, fmt.Errorf("repository path is invalid")
	}
	if strings.TrimSpace(repository) == "" {
		return "", false, nil
	}

	return repository, true, nil
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

func requireSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("request body must contain a single JSON object")
}

func classifyScanError(err error) (int, string, string) {
	switch {
	case scanservice.IsSaveError(err):
		return http.StatusServiceUnavailable, "storage_unavailable", "the scan completed, but its result could not be stored"
	case jobs.IsIncomplete(err):
		var incomplete *jobs.IncompleteError
		if errors.As(err, &incomplete) && incomplete != nil {
			return http.StatusUnprocessableEntity, "scan_incomplete", fmt.Sprintf(
				"scan coverage is %s: %d manifest(s) completed, %d failed",
				incomplete.Status,
				incomplete.CompletedManifestCount,
				incomplete.FailedManifestCount,
			)
		}
		return http.StatusUnprocessableEntity, "scan_incomplete", "the scan did not cover every selected manifest"
	case limits.IsExceeded(err):
		return http.StatusUnprocessableEntity, "scan_limit_exceeded", err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "scan_timeout", "the scan exceeded its configured deadline"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "scan_canceled", "the scan was canceled"
	default:
		return http.StatusBadGateway, "scan_failed", "the registry scan could not be completed"
	}
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
}

func (w *apiResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *apiResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *apiResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (h *Handler) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
				slog.Error("panic serving api request", "panic_type", fmt.Sprintf("%T", recovered), "request_id", requestID)
				if !wrapped.wroteHeader {
					writeAPIError(wrapped, http.StatusInternalServerError, "internal_error", "an internal error occurred")
				}
			}
		}()
		next.ServeHTTP(wrapped, request)
	})
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
	return &errorResponse{
		Code:      code,
		Message:   message,
		RequestID: requestIDFromWriter(writer),
	}
}

func requestIDFromWriter(writer http.ResponseWriter) string {
	for {
		wrapped, ok := writer.(*apiResponseWriter)
		if !ok {
			return ""
		}
		if wrapped.requestID != "" {
			return wrapped.requestID
		}
		writer = wrapped.ResponseWriter
	}
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
	return value
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

func safeDiagnosticMessage(code string) string {
	switch code {
	case "files_skipped_oversize":
		return "one or more files exceeded the configured per-file scan limit"
	case "max_findings_exceeded":
		return "the scan exceeded the configured findings limit"
	case "max_raw_finding_bytes_exceeded":
		return "the scan exceeded the configured raw finding byte limit"
	default:
		return "scan step failed"
	}
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
