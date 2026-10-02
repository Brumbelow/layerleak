package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// metricsContentType is the Prometheus text exposition format 0.0.4.
const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// routeNone labels requests the mux never matched (unclean paths, refused
// credentials, drain refusals). Route labels are always mux patterns or this
// constant, never request paths, so label cardinality stays bounded and no
// repository name or reference reaches the metrics.
const routeNone = "none"

// durationBuckets are the fixed request-duration histogram bounds in seconds.
// They span a readiness probe to a 30-minute scan.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800}

type requestKey struct {
	route       string
	statusClass string
}

type histogram struct {
	counts []uint64 // one per bucket bound, cumulative at render time
	sum    float64
	count  uint64
}

// metrics is the API's in-process Prometheus registry. It is hand-rolled so
// the scratch image takes on no telemetry dependency. Every label value is a
// fixed string chosen by the server.
type metrics struct {
	version   string
	startTime time.Time
	inFlight  atomic.Int64

	mu         sync.Mutex
	requests   map[requestKey]uint64
	durations  map[string]*histogram
	scans      map[string]uint64
	scanErrors map[string]uint64
}

func newMetrics(version string, startTime time.Time) *metrics {
	return &metrics{
		version:    version,
		startTime:  startTime,
		requests:   make(map[requestKey]uint64),
		durations:  make(map[string]*histogram),
		scans:      make(map[string]uint64),
		scanErrors: make(map[string]uint64),
	}
}

func routeLabel(pattern string) string {
	if strings.TrimSpace(pattern) == "" {
		return routeNone
	}
	return pattern
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "unknown"
	}
	return strconv.Itoa(status/100) + "xx"
}

// observeRequest counts one served request and its wall-clock duration.
func (m *metrics) observeRequest(route string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	seconds := duration.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{route: route, statusClass: statusClass(status)}]++
	entry, ok := m.durations[route]
	if !ok {
		entry = &histogram{counts: make([]uint64, len(durationBuckets))}
		m.durations[route] = entry
	}
	for index, bound := range durationBuckets {
		if seconds <= bound {
			entry.counts[index]++
			break
		}
	}
	entry.sum += seconds
	entry.count++
}

// observeScan records the outcome of one scan the handler ran.
func (m *metrics) observeScan(outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scans[outcome]++
}

// observeScanError counts one failed POST /api/v1/scans by its error code.
func (m *metrics) observeScanError(code string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanErrors[code]++
}

func (m *metrics) scanStarted() {
	if m != nil {
		m.inFlight.Add(1)
	}
}

func (m *metrics) scanFinished() {
	if m != nil {
		m.inFlight.Add(-1)
	}
}

// write renders the exposition. Families and label sets are emitted in sorted
// order so two scrapes of the same state are byte-identical. The whole page is
// rendered into memory under the mutex and written to the destination only
// after the mutex is released: a scrape client that stops reading must stall
// its own handler, never the observeRequest call every API request makes.
// The page size is bounded by route-pattern and error-code cardinality.
func (m *metrics) write(destination io.Writer) error {
	page := m.render()
	_, err := destination.Write(page.Bytes())
	return err
}

// render snapshots the registry into one exposition page under the mutex.
func (m *metrics) render() *bytes.Buffer {
	writer := &bytes.Buffer{}
	m.mu.Lock()
	defer m.mu.Unlock()

	writeFamily(writer, "layerleak_build_info", "gauge", "Build information about the serving binary; the value is always 1.")
	writeSample(writer, "layerleak_build_info", labels{{"version", m.version}}, "1")

	writeFamily(writer, "layerleak_process_start_time_seconds", "gauge", "Unix time at which the API process started.")
	writeSample(writer, "layerleak_process_start_time_seconds", nil, formatFloat(float64(m.startTime.UnixNano())/1e9))

	writeFamily(writer, "layerleak_api_requests_total", "counter", "Requests served, by mux route pattern and status class.")
	requestKeys := make([]requestKey, 0, len(m.requests))
	for key := range m.requests {
		requestKeys = append(requestKeys, key)
	}
	sort.Slice(requestKeys, func(i, j int) bool {
		if requestKeys[i].route != requestKeys[j].route {
			return requestKeys[i].route < requestKeys[j].route
		}
		return requestKeys[i].statusClass < requestKeys[j].statusClass
	})
	for _, key := range requestKeys {
		writeSample(writer, "layerleak_api_requests_total", labels{{"route", key.route}, {"status_class", key.statusClass}}, formatUint(m.requests[key]))
	}

	writeFamily(writer, "layerleak_api_request_duration_seconds", "histogram", "Request duration in seconds, by mux route pattern.")
	for _, route := range slices.Sorted(maps.Keys(m.durations)) {
		entry := m.durations[route]
		cumulative := uint64(0)
		for index, bound := range durationBuckets {
			cumulative += entry.counts[index]
			writeSample(writer, "layerleak_api_request_duration_seconds_bucket", labels{{"route", route}, {"le", formatFloat(bound)}}, formatUint(cumulative))
		}
		writeSample(writer, "layerleak_api_request_duration_seconds_bucket", labels{{"route", route}, {"le", "+Inf"}}, formatUint(entry.count))
		writeSample(writer, "layerleak_api_request_duration_seconds_sum", labels{{"route", route}}, formatFloat(entry.sum))
		writeSample(writer, "layerleak_api_request_duration_seconds_count", labels{{"route", route}}, formatUint(entry.count))
	}

	writeFamily(writer, "layerleak_scans_total", "counter", "Scans run by POST /api/v1/scans, by outcome (completed, partial or failed).")
	for _, outcome := range slices.Sorted(maps.Keys(m.scans)) {
		writeSample(writer, "layerleak_scans_total", labels{{"outcome", outcome}}, formatUint(m.scans[outcome]))
	}

	writeFamily(writer, "layerleak_scan_errors_total", "counter", "POST /api/v1/scans requests that answered an error, by error code.")
	for _, code := range slices.Sorted(maps.Keys(m.scanErrors)) {
		writeSample(writer, "layerleak_scan_errors_total", labels{{"code", code}}, formatUint(m.scanErrors[code]))
	}

	writeFamily(writer, "layerleak_scans_in_flight", "gauge", "Scans currently running.")
	writeSample(writer, "layerleak_scans_in_flight", nil, strconv.FormatInt(m.inFlight.Load(), 10))

	return writer
}

type label struct {
	name  string
	value string
}

type labels []label

func writeFamily(writer *bytes.Buffer, name, kind, help string) {
	_, _ = writer.WriteString("# HELP " + name + " " + escapeHelp(help) + "\n")
	_, _ = writer.WriteString("# TYPE " + name + " " + kind + "\n")
}

func writeSample(writer *bytes.Buffer, name string, set labels, value string) {
	_, _ = writer.WriteString(name)
	if len(set) > 0 {
		_, _ = writer.WriteString("{")
		for index, item := range set {
			if index > 0 {
				_, _ = writer.WriteString(",")
			}
			_, _ = writer.WriteString(item.name + `="` + escapeLabelValue(item.value) + `"`)
		}
		_, _ = writer.WriteString("}")
	}
	_, _ = writer.WriteString(" " + value + "\n")
}

// escapeLabelValue applies the exposition-format escapes: backslash, double
// quote and line feed.
func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

// escapeHelp applies the HELP-line escapes: backslash and line feed.
func escapeHelp(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func formatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// MetricsHandler serves the Prometheus exposition at GET /metrics. It is
// meant for the separate metrics listener (LAYERLEAK_API_METRICS_ADDR) and is
// never mounted on the API mux, so it carries no bearer-token check of its own.
// Each response carries the API's response write deadline so a scraper that
// stops reading is abandoned instead of pinning a handler goroutine.
func (h *Handler) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(h.options.ResponseTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			h.logger.Warn("set metrics response deadline", "error_type", fmt.Sprintf("%T", err))
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.URL.Path != "/metrics" {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", metricsContentType)
		if request.Method == http.MethodHead {
			writer.WriteHeader(http.StatusOK)
			return
		}
		if err := h.metrics.write(writer); err != nil {
			h.logger.Warn("write metrics exposition", "error_type", fmt.Sprintf("%T", err))
		}
	})
}
