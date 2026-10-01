package registry

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// StatusError reports a registry or token-endpoint response outside the 2xx
// range. Auth marks token-endpoint responses. URL carries only scheme, host and
// path so pre-signed query credentials never reach logs; Error() never echoes
// response bodies or headers.
type StatusError struct {
	StatusCode int
	Method     string
	URL        string
	Auth       bool
}

func (e *StatusError) Error() string {
	prefix := "registry request failed"
	if e.Auth {
		prefix = "auth request failed"
	}
	if text := http.StatusText(e.StatusCode); text != "" {
		return fmt.Sprintf("%s: status=%d %s", prefix, e.StatusCode, text)
	}
	return fmt.Sprintf("%s: status=%d", prefix, e.StatusCode)
}

// StatusCode returns the HTTP status of the StatusError in err's chain.
func StatusCode(err error) (int, bool) {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode, true
	}
	return 0, false
}

// IsNotFound reports whether err is a registry 404 (missing repository,
// manifest, tag or blob). Token-endpoint responses are not counted.
func IsNotFound(err error) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && !statusErr.Auth && statusErr.StatusCode == http.StatusNotFound
}

// IsRateLimited reports whether err is a 429 from the registry or its token
// endpoint.
func IsRateLimited(err error) bool {
	code, ok := StatusCode(err)
	return ok && code == http.StatusTooManyRequests
}

// IsUnauthorized reports whether err is a 401 or 403 from the registry or its
// token endpoint.
func IsUnauthorized(err error) bool {
	code, ok := StatusCode(err)
	return ok && (code == http.StatusUnauthorized || code == http.StatusForbidden)
}

// IsServerError reports whether err is a 5xx from the registry or its token
// endpoint.
func IsServerError(err error) bool {
	code, ok := StatusCode(err)
	return ok && code >= 500 && code <= 599
}

// RequestError reports a transport-level failure (dial, TLS, redirect policy,
// timeout) for a request. URL is redacted to scheme, host and path because
// blob redirects carry pre-signed credentials in the query string. Err is the
// underlying cause and is reachable through errors.Is and errors.As.
type RequestError struct {
	Method string
	URL    string
	Err    error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%s %q: %v", e.Method, e.URL, e.Err)
}

func (e *RequestError) Unwrap() error {
	return e.Err
}

// redactURL keeps scheme, host and path of a URL and drops userinfo, query and
// fragment. Unparseable input is replaced wholesale.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<redacted>"
	}
	redacted := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}
	return redacted.String()
}

// wrapTransportError converts the *url.Error produced by http.Client into a
// RequestError with a redacted target. Other errors pass through unchanged.
func wrapTransportError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return &RequestError{Method: urlErr.Op, URL: redactURL(urlErr.URL), Err: urlErr.Err}
	}
	return err
}
