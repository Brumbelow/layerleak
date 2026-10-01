package registry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
)

// recordingSleeper replaces the client's backoff sleep so tests can assert the
// computed delays without waiting for them.
type recordingSleeper struct {
	delays []time.Duration
	err    error
}

func (s *recordingSleeper) sleep(_ context.Context, delay time.Duration) error {
	s.delays = append(s.delays, delay)
	return s.err
}

func newRetryClient(t *testing.T, attempts int, transport http.RoundTripper) (*Client, *recordingSleeper) {
	t.Helper()
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestAttempts:   attempts,
		HTTPClient:        &http.Client{Transport: transport},
	})
	sleeper := &recordingSleeper{}
	client.sleep = sleeper.sleep
	client.now = func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }
	return client, sleeper
}

func TestRetryHonoursRetryAfterSeconds(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusTooManyRequests, "text/plain", nil, map[string]string{"Retry-After": "2"}), nil
	})
	client, sleeper := newRetryClient(t, 3, transport)

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !IsRateLimited(err) {
		t.Fatalf("FetchManifest() error = %v, want the final 429 as a typed rate limit", err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d", requests)
	}
	if len(sleeper.delays) != 2 || sleeper.delays[0] != 2*time.Second || sleeper.delays[1] != 2*time.Second {
		t.Fatalf("delays = %v, want two 2s waits from Retry-After", sleeper.delays)
	}
}

func TestRetryHonoursRetryAfterHTTPDateAndCapsIt(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{name: "http date", header: "Wed, 30 Sep 2026 12:00:03 GMT", want: 3 * time.Second},
		{name: "date in the past", header: "Wed, 30 Sep 2026 11:00:00 GMT", want: 0},
		{name: "excessive seconds are capped", header: "3600", want: retryMaxRetryAfter},
		{name: "negative seconds", header: "-5", want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusServiceUnavailable, "text/plain", nil, map[string]string{"Retry-After": test.header}), nil
			})
			client, sleeper := newRetryClient(t, 2, transport)
			if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); !IsServerError(err) {
				t.Fatalf("FetchManifest() error = %v", err)
			}
			if len(sleeper.delays) != 1 || sleeper.delays[0] != test.want {
				t.Fatalf("delays = %v, want [%s]", sleeper.delays, test.want)
			}
		})
	}
}

func TestRetryBacksOffExponentiallyWithJitter(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusBadGateway, "text/plain", nil, map[string]string{"Retry-After": "not-a-date"}), nil
	})
	client, sleeper := newRetryClient(t, 7, transport)

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); !IsServerError(err) {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if requests != 7 || len(sleeper.delays) != 6 {
		t.Fatalf("requests = %d delays = %v", requests, sleeper.delays)
	}
	expected := retryBaseDelay
	for index, delay := range sleeper.delays {
		lower, upper := expected/2, expected
		if delay < lower || delay >= upper {
			t.Fatalf("delay[%d] = %s, want within [%s, %s)", index, delay, lower, upper)
		}
		expected = min(expected*2, retryMaxDelay)
	}
	if sleeper.delays[5] >= retryMaxDelay || sleeper.delays[5] < retryMaxDelay/2 {
		t.Fatalf("delay[5] = %s, want capped by %s", sleeper.delays[5], retryMaxDelay)
	}
}

func TestRetryStopsWhenCallerCancelsDuringBackoff(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusServiceUnavailable, "text/plain", nil, nil), nil
	})
	client, sleeper := newRetryClient(t, 3, transport)
	sleeper.err = context.Canceled

	_, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if !errors.Is(err, context.Canceled) || !IsServerError(err) {
		t.Fatalf("FetchManifest() error = %v, want both the cancellation and the last status", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestRetryableStatusTable(t *testing.T) {
	for status, want := range map[int]bool{
		http.StatusOK:                      false,
		http.StatusNotFound:                false,
		http.StatusUnauthorized:            false,
		http.StatusRequestTimeout:          true,
		http.StatusTooManyRequests:         true,
		http.StatusInternalServerError:     true,
		http.StatusNotImplemented:          false,
		http.StatusBadGateway:              true,
		http.StatusServiceUnavailable:      true,
		http.StatusGatewayTimeout:          true,
		http.StatusHTTPVersionNotSupported: false,
		599:                                true,
	} {
		if got := isRetryableStatus(status); got != want {
			t.Fatalf("isRetryableStatus(%d) = %t, want %t", status, got, want)
		}
	}
}

func TestNotImplementedIsNotRetried(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusNotImplemented, "text/plain", nil, nil), nil
	})
	client, sleeper := newRetryClient(t, 3, transport)
	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); !IsServerError(err) {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if requests != 1 || len(sleeper.delays) != 0 {
		t.Fatalf("requests = %d delays = %v", requests, sleeper.delays)
	}
}

func TestNonIdempotentRequestsAreNotRetried(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusServiceUnavailable, "text/plain", nil, nil), nil
	})
	client, _ := newRetryClient(t, 3, transport)
	response, err := client.executeRequest(context.Background(), http.MethodPost, "https://registry.test/v2/", "", "")
	if err != nil {
		t.Fatalf("executeRequest() error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || requests != 1 {
		t.Fatalf("status = %d requests = %d", response.StatusCode, requests)
	}
}

func TestRetryableRequestErrorClassification(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "nil", ctx: context.Background()},
		{name: "attempt deadline", ctx: context.Background(), err: &RequestError{Method: "Get", URL: "https://registry.test/v2/", Err: context.DeadlineExceeded}, want: true},
		{name: "dial failure", ctx: context.Background(), err: &RequestError{Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}, want: true},
		{name: "truncated response", ctx: context.Background(), err: &RequestError{Err: errors.Join(errors.New("read manifest"), errUnexpectedEOF())}, want: true},
		{name: "policy rejection", ctx: context.Background(), err: &RequestError{Err: errors.New("non-public registry address 127.0.0.1 is not allowed")}},
		{name: "caller canceled", ctx: canceled, err: &RequestError{Err: context.DeadlineExceeded}},
		{name: "attempt canceled", ctx: context.Background(), err: &RequestError{Err: context.Canceled}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isRetryableRequestError(test.ctx, test.err); got != test.want {
				t.Fatalf("isRetryableRequestError() = %t, want %t", got, test.want)
			}
		})
	}
}

func errUnexpectedEOF() error {
	return &net.OpError{Op: "read", Err: errors.New("unexpected EOF")}
}

func TestStalledFirstAttemptIsRetriedWithFreshDeadline(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}
		return jsonResponse(http.StatusOK, manifest.MediaTypeOCIImageManifest, []byte(`{"schemaVersion":2}`), map[string]string{
			"Docker-Content-Digest": "sha256:" + strings.Repeat("a", 64),
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestTimeout:    30 * time.Millisecond,
		RequestAttempts:   3,
		HTTPClient:        &http.Client{Transport: transport},
	})
	client.sleep = func(context.Context, time.Duration) error { return nil }

	response, err := client.FetchManifest(context.Background(), "library/app", "latest")
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if requests != 2 || string(response.Body) != `{"schemaVersion":2}` {
		t.Fatalf("requests = %d body = %q", requests, response.Body)
	}
}

func TestBlobHeaderPhaseIsBoundedByRequestTimeout(t *testing.T) {
	digest := "sha256:" + strings.Repeat("e", 64)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		RequestTimeout:    20 * time.Millisecond,
		RequestAttempts:   1,
		HTTPClient:        &http.Client{Transport: transport},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	started := time.Now()
	_, err := client.OpenBlob(ctx, "library/app", digest)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenBlob() error = %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("OpenBlob() took %s", time.Since(started))
	}
}

func TestAttemptContextDetachesFromTimeout(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	attempt := newAttemptContext(parent, 20*time.Millisecond)
	if _, ok := attempt.Deadline(); !ok {
		t.Fatal("Deadline() ok = false before detach")
	}
	attempt.detach()
	if _, ok := attempt.Deadline(); ok {
		t.Fatal("Deadline() ok = true after detach")
	}
	select {
	case <-attempt.Done():
		t.Fatal("detached attempt expired")
	case <-time.After(60 * time.Millisecond):
	}
	cancelParent()
	select {
	case <-attempt.Done():
	case <-time.After(time.Second):
		t.Fatal("attempt did not follow parent cancellation")
	}
	if !errors.Is(attempt.Err(), context.Canceled) {
		t.Fatalf("Err() = %v", attempt.Err())
	}
	attempt.cancel()

	expiring := newAttemptContext(context.Background(), 5*time.Millisecond)
	defer expiring.cancel()
	select {
	case <-expiring.Done():
	case <-time.After(time.Second):
		t.Fatal("attempt did not expire")
	}
	if !errors.Is(expiring.Err(), context.DeadlineExceeded) {
		t.Fatalf("Err() = %v", expiring.Err())
	}
}
