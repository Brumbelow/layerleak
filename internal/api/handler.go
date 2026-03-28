package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
	"github.com/brumbelow/layerleak/internal/scanservice"
	"github.com/brumbelow/layerleak/internal/storage"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

type scanExecutor interface {
	ScanAndSave(rctx context.Context, request scanservice.Request) (jobs.Result, error)
}

type Handler struct {
	scanner scanExecutor
	store   storage.ReadStore
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type scanRequest struct {
	Reference string `json:"reference"`
	Platform  string `json:"platform,omitempty"`
}

type scanResponse struct {
	Result *jobs.Result   `json:"result,omitempty"`
	Error  *errorResponse `json:"error,omitempty"`
}

type repositoriesResponse struct {
	Repositories []repositoryItem `json:"repositories"`
	Limit        int              `json:"limit"`
	Offset       int              `json:"offset"`
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

func NewHandler(scanner scanExecutor, store storage.ReadStore) http.Handler {
	handler := &Handler{
		scanner: scanner,
		store:   store,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/scans", handler.handleScan)
	mux.HandleFunc("GET /api/v1/repositories", handler.handleListRepositories)
	mux.HandleFunc("GET /api/v1/repositories/", handler.handleRepositorySubtree)
	mux.HandleFunc("GET /api/v1/findings/{id}", handler.handleGetFinding)
	return mux
}

func (h *Handler) handleScan(writer http.ResponseWriter, request *http.Request) {
	if h.scanner == nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "scan service is not configured")
		return
	}

	var body scanRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", invalidBodyMessage(err))
		return
	}
	if err := requireSingleJSONValue(decoder); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	reference, err := manifest.ParseReference(body.Reference)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.scanner.ScanAndSave(request.Context(), scanservice.Request{
		Reference: reference,
		Platform:  strings.TrimSpace(body.Platform),
	})
	if err != nil {
		response := scanResponse{
			Error: &errorResponse{
				Code:    scanErrorCode(err),
				Message: err.Error(),
			},
		}
		if hasResult(result) {
			response.Result = &result
		}
		writeJSON(writer, http.StatusInternalServerError, response)
		return
	}

	writeJSON(writer, http.StatusOK, scanResponse{Result: &result})
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

	items, err := h.store.ListRepositories(request.Context(), limit, offset)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", err.Error())
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

	prefix := "/api/v1/repositories/"
	path := request.URL.Path
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/findings") {
		http.NotFound(writer, request)
		return
	}

	rawRepository := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/findings")
	repository, err := url.PathUnescape(strings.Trim(rawRepository, "/"))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "repository path is invalid")
		return
	}
	if strings.TrimSpace(repository) == "" {
		http.NotFound(writer, request)
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

	items, err := h.store.ListRepositoryFindings(request.Context(), repository, disposition, limit, offset)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", err.Error())
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

	item, err := h.store.GetFinding(request.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(writer, http.StatusNotFound, "not_found", "finding not found")
			return
		}
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", err.Error())
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
		return fmt.Errorf("request body must be valid JSON")
	}
	return fmt.Errorf("request body must contain a single JSON object")
}

func scanErrorCode(err error) string {
	if scanservice.IsSaveError(err) {
		return "storage_failed"
	}
	return "scan_failed"
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
		"error": errorResponse{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(writer http.ResponseWriter, statusCode int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}
