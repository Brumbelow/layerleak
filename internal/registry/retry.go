package registry

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// retryBaseDelay is the first backoff step; later steps double it.
	retryBaseDelay = 250 * time.Millisecond
	// retryMaxDelay caps the computed exponential backoff.
	retryMaxDelay = 5 * time.Second
	// retryMaxRetryAfter caps a server-provided Retry-After so a hostile or
	// misconfigured registry cannot park a scan for hours.
	retryMaxRetryAfter = 30 * time.Second
)

// retryDelay returns how long to wait before retrying after the attempt with
// the given zero-based index failed. A Retry-After header (seconds or HTTP-date)
// wins when present; otherwise the delay grows exponentially with equal jitter.
func (c *Client) retryDelay(attempt int, response *http.Response) time.Duration {
	if response != nil {
		if wait, ok := parseRetryAfter(response.Header.Get("Retry-After"), c.now()); ok {
			return min(wait, retryMaxRetryAfter)
		}
	}
	backoff := retryBaseDelay
	for index := 0; index < attempt && backoff < retryMaxDelay; index++ {
		backoff *= 2
	}
	backoff = min(backoff, retryMaxDelay)
	half := backoff / 2
	return half + rand.N(half) //nolint:gosec // backoff jitter is not security sensitive
}

// parseRetryAfter reads a Retry-After value as delay-seconds or an HTTP-date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if when, err := http.ParseTime(value); err == nil {
		return max(when.Sub(now), 0), true
	}
	return 0, false
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// isRetryableStatus reports whether a response status is worth another
// idempotent attempt: request timeout, rate limiting and server failures,
// except 501 and 505 which never clear on their own.
func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	case http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
		return false
	default:
		return statusCode >= 500 && statusCode <= 599
	}
}

// isRetryableRequestError reports whether a transport failure is transient:
// attempt deadlines, network timeouts, connection-level failures and truncated
// responses. Policy rejections (address, scheme, redirect, TLS verification)
// are not, and nothing is retried once the caller's context is done.
func isRetryableRequestError(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

type streamBodyKey struct{}

// withStreamingBody marks a request whose body is bounded by the caller's
// context rather than the request timeout (blob downloads). The request
// timeout then covers only the time to response headers.
func withStreamingBody(ctx context.Context) context.Context {
	return context.WithValue(ctx, streamBodyKey{}, true)
}

func streamingBodyFromContext(ctx context.Context) bool {
	streaming, ok := ctx.Value(streamBodyKey{}).(bool)
	return ok && streaming && requestKindFromContext(ctx) != requestKindAuth
}

// attemptContext is the context of one request attempt. It expires with the
// configured request timeout like context.WithTimeout (Err reports
// context.DeadlineExceeded) but the timer can be detached once response headers
// arrive, so a streaming body stays bounded by the caller's context only.
type attemptContext struct {
	context.Context
	done     chan struct{}
	timer    *time.Timer
	stop     func() bool
	mu       sync.Mutex
	err      error
	deadline time.Time
	detached bool
}

func newAttemptContext(parent context.Context, timeout time.Duration) *attemptContext {
	attempt := &attemptContext{Context: parent, done: make(chan struct{})}
	if timeout > 0 {
		attempt.deadline = time.Now().Add(timeout)
		attempt.timer = time.AfterFunc(timeout, func() { attempt.finish(context.DeadlineExceeded) })
	}
	attempt.stop = context.AfterFunc(parent, func() { attempt.finish(parent.Err()) })
	return attempt
}

func (a *attemptContext) Done() <-chan struct{} {
	return a.done
}

func (a *attemptContext) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

func (a *attemptContext) Deadline() (time.Time, bool) {
	a.mu.Lock()
	deadline, detached := a.deadline, a.detached
	a.mu.Unlock()
	parentDeadline, ok := a.Context.Deadline()
	if detached || deadline.IsZero() {
		return parentDeadline, ok
	}
	if ok && parentDeadline.Before(deadline) {
		return parentDeadline, true
	}
	return deadline, true
}

// detach stops the attempt timer; the context then ends only with its parent
// or an explicit cancel.
func (a *attemptContext) detach() {
	a.mu.Lock()
	a.detached = true
	timer := a.timer
	a.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

// cancel ends the attempt (idempotent) and releases its timers.
func (a *attemptContext) cancel() {
	a.finish(context.Canceled)
	a.stop()
	a.detach()
}

func (a *attemptContext) finish(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return
	}
	a.err = err
	close(a.done)
}

// attemptBody ties the attempt context to the response body: closing the body
// releases the attempt's timers and context.
type attemptBody struct {
	io.ReadCloser
	cancel func()
	once   sync.Once
}

func (b *attemptBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)
	return err
}
