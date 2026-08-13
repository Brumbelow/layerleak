package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brumbelow/layerleak/internal/limits"
	"github.com/brumbelow/layerleak/internal/manifest"
	distributionreference "github.com/distribution/reference"
)

const (
	maxTokenCacheEntries           = 128
	maxTokenCacheBytes             = 1 << 20
	maxRegistryResponseHeaderBytes = 1 << 20
)

type Options struct {
	BaseURL                     string
	AuthURL                     string
	HTTPClient                  *http.Client
	RequestTimeout              time.Duration
	RequestAttempts             int
	MaxManifestBytes            int64
	MaxTagResponseBytes         int64
	MaxAuthResponseBytes        int64
	MaxRedirects                int
	AllowedPrivateRegistryHosts []string
	AllowedPrivateAuthHosts     []string
	AllowPrivateHosts           bool
	LookupIP                    func(context.Context, string) ([]net.IPAddr, error)
}

type Client struct {
	baseURL                     *url.URL
	authURL                     *url.URL
	httpClient                  *http.Client
	requestTimeout              time.Duration
	requestAttempts             int
	maxManifestBytes            int64
	maxTagResponseBytes         int64
	maxAuthResponseBytes        int64
	maxRedirects                int
	allowedPrivateRegistryHosts map[string]struct{}
	allowedPrivateAuthHosts     map[string]struct{}
	allowPrivateHosts           bool
	lookupIP                    func(context.Context, string) ([]net.IPAddr, error)
	configErr                   error
	tokenCache                  map[string]string
	tokenCacheBytes             int
	tokenCacheMu                sync.Mutex
}

type ManifestResponse struct {
	Digest    string
	MediaType string
	Size      int64
	Body      []byte
}

type ManifestMetadata struct {
	Digest    string
	MediaType string
}

type BlobResponse struct {
	Digest    string
	MediaType string
	Size      int64
	Body      io.ReadCloser
}

type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

// BaseURLForRegistry returns the HTTPS base URL for a parsed registry host.
// Docker Hub canonicalizes to registry-1.docker.io; any other host passes through as https://{host}.
func BaseURLForRegistry(registry string) string {
	value := strings.TrimSpace(registry)
	if value == "" || value == manifest.DockerHubRegistry {
		return "https://registry-1.docker.io"
	}
	return "https://" + value
}

func NewClient(options Options) *Client {
	registryAllowlist, registryAllowlistErr := normalizeHostAllowlist(options.AllowedPrivateRegistryHosts)
	authAllowlist, authAllowlistErr := normalizeHostAllowlist(options.AllowedPrivateAuthHosts)
	allowConfiguredHTTP := len(registryAllowlist) > 0 || len(authAllowlist) > 0
	baseURL, baseErr := parseConfiguredEndpointURL(defaultString(options.BaseURL, "https://registry-1.docker.io"), allowConfiguredHTTP)
	authURL, authErr := parseConfiguredEndpointURL(defaultString(options.AuthURL, "https://auth.docker.io/token"), allowConfiguredHTTP)
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	lookupIP := options.LookupIP
	if lookupIP == nil {
		lookupIP = net.DefaultResolver.LookupIPAddr
	}
	requestAttempts := options.RequestAttempts
	if requestAttempts <= 0 {
		requestAttempts = 2
	}
	maxRedirects := options.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 3
	}
	client := &Client{
		baseURL:                     baseURL,
		authURL:                     authURL,
		httpClient:                  httpClient,
		requestTimeout:              options.RequestTimeout,
		requestAttempts:             requestAttempts,
		maxManifestBytes:            options.MaxManifestBytes,
		maxTagResponseBytes:         options.MaxTagResponseBytes,
		maxAuthResponseBytes:        options.MaxAuthResponseBytes,
		maxRedirects:                maxRedirects,
		allowedPrivateRegistryHosts: registryAllowlist,
		allowedPrivateAuthHosts:     authAllowlist,
		allowPrivateHosts:           options.AllowPrivateHosts,
		lookupIP:                    lookupIP,
		configErr:                   errors.Join(baseErr, authErr, registryAllowlistErr, authAllowlistErr),
		tokenCache:                  make(map[string]string),
	}
	client.validateConfiguredEndpointSchemes()
	client.hardenHTTPClient()
	return client
}

func (c *Client) BaseURL() string {
	if c.baseURL == nil {
		return ""
	}

	return c.baseURL.String()
}

func (c *Client) AuthURL() string {
	if c.authURL == nil {
		return ""
	}

	return c.authURL.String()
}

func (c *Client) ManifestURL(repository, identifier string) string {
	return c.join("v2", repository, "manifests", identifier)
}

func (c *Client) BlobURL(repository, digest string) string {
	return c.join("v2", repository, "blobs", digest)
}

func (c *Client) TagsURL(repository string) string {
	return c.join("v2", repository, "tags", "list")
}

func (c *Client) FetchManifest(ctx context.Context, repository, identifier string) (ManifestResponse, error) {
	requestCtx, cancel := c.withRequestTimeout(ctx)
	defer cancel()
	response, err := c.doRequest(requestCtx, http.MethodGet, c.ManifestURL(repository, identifier), strings.Join([]string{
		manifest.MediaTypeOCIImageIndex,
		manifest.MediaTypeOCIImageManifest,
		manifest.MediaTypeDockerSchema2ManifestList,
		manifest.MediaTypeDockerSchema2Manifest,
	}, ", "), repository)
	if err != nil {
		return ManifestResponse{}, err
	}
	defer response.Body.Close()

	body, err := readManifestBody(response.Body, c.maxManifestBytes, identifier)
	if err != nil {
		return ManifestResponse{}, err
	}

	return ManifestResponse{
		Digest:    strings.TrimSpace(response.Header.Get("Docker-Content-Digest")),
		MediaType: strings.TrimSpace(response.Header.Get("Content-Type")),
		Size:      int64(len(body)),
		Body:      body,
	}, nil
}

func (c *Client) ResolveManifest(ctx context.Context, repository, identifier string) (ManifestMetadata, error) {
	headCtx, cancel := c.withRequestTimeout(ctx)
	response, err := c.doRequest(headCtx, http.MethodHead, c.ManifestURL(repository, identifier), strings.Join([]string{
		manifest.MediaTypeOCIImageIndex,
		manifest.MediaTypeOCIImageManifest,
		manifest.MediaTypeDockerSchema2ManifestList,
		manifest.MediaTypeDockerSchema2Manifest,
	}, ", "), repository)
	if err == nil {
		response.Body.Close()
		cancel()
		resolved := ManifestMetadata{
			Digest:    strings.TrimSpace(response.Header.Get("Docker-Content-Digest")),
			MediaType: strings.TrimSpace(response.Header.Get("Content-Type")),
		}
		if resolved.Digest != "" {
			if err := manifest.ValidateDigest(resolved.Digest); err != nil {
				return ManifestMetadata{}, fmt.Errorf("validate resolved manifest digest: %w", err)
			}
			return resolved, nil
		}
	} else {
		cancel()
	}

	manifestResponse, err := c.FetchManifest(ctx, repository, identifier)
	if err != nil {
		return ManifestMetadata{}, err
	}
	resolvedDigest := manifestResponse.Digest
	if resolvedDigest == "" {
		resolvedDigest, err = manifest.DigestBytes("sha256", manifestResponse.Body)
		if err != nil {
			return ManifestMetadata{}, err
		}
	}
	if err := manifest.ValidateDigest(resolvedDigest); err != nil {
		return ManifestMetadata{}, fmt.Errorf("validate resolved manifest digest: %w", err)
	}

	return ManifestMetadata{
		Digest:    resolvedDigest,
		MediaType: manifestResponse.MediaType,
	}, nil
}

func (c *Client) OpenBlob(ctx context.Context, repository, digest string) (BlobResponse, error) {
	if err := manifest.ValidateDigest(digest); err != nil {
		return BlobResponse{}, fmt.Errorf("validate blob digest: %w", err)
	}
	response, err := c.doRequest(ctx, http.MethodGet, c.BlobURL(repository, digest), "", repository)
	if err != nil {
		return BlobResponse{}, err
	}

	return BlobResponse{
		Digest:    strings.TrimSpace(response.Header.Get("Docker-Content-Digest")),
		MediaType: strings.TrimSpace(response.Header.Get("Content-Type")),
		Size:      response.ContentLength,
		Body:      response.Body,
	}, nil
}

func (c *Client) ListTags(ctx context.Context, repository string, pageSize, maxTags int) ([]string, error) {
	if pageSize <= 0 {
		pageSize = 100
	}

	targetURL, err := appendURLQuery(c.TagsURL(repository), map[string]string{
		"n": fmt.Sprintf("%d", pageSize),
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	seenPages := make(map[string]struct{})
	tags := make([]string, 0)
	for {
		if _, ok := seenPages[targetURL]; ok {
			sort.Strings(tags)
			return tags, fmt.Errorf("registry tag pagination cycle detected")
		}
		seenPages[targetURL] = struct{}{}
		pageCtx, cancel := c.withRequestTimeout(ctx)
		response, err := c.doRequest(pageCtx, http.MethodGet, targetURL, "application/json", repository)
		if err != nil {
			cancel()
			return nil, err
		}

		var payload struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		linkHeader := response.Header.Get("Link")
		body, readErr := readTagResponseBody(response.Body, c.maxTagResponseBytes, repository)
		response.Body.Close()
		cancel()
		if readErr != nil {
			sort.Strings(tags)
			return tags, readErr
		}
		if decodeErr := json.Unmarshal(body, &payload); decodeErr != nil {
			return nil, fmt.Errorf("decode tags response: %w", decodeErr)
		}

		for _, tag := range payload.Tags {
			if !isValidTag(tag) {
				sort.Strings(tags)
				return tags, fmt.Errorf("registry returned invalid tag syntax")
			}
		}

		uniqueBefore := len(tags)
		for _, tag := range payload.Tags {
			if _, ok := seen[tag]; ok {
				continue
			}
			if maxTags > 0 && len(tags) >= maxTags {
				sort.Strings(tags)
				return tags, limits.NewExceeded(limits.KindRepositoryTags, int64(maxTags), "repository "+repository)
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}

		nextURL, ok, err := c.nextLinkURL(ctx, targetURL, linkHeader)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if len(tags) == uniqueBefore {
			sort.Strings(tags)
			return tags, fmt.Errorf("registry tag pagination did not add any new tags")
		}
		targetURL = nextURL
	}

	sort.Strings(tags)
	return tags, nil
}

func (c *Client) doRequest(ctx context.Context, method, targetURL, accept, repository string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.configErr != nil {
		return nil, c.configErr
	}
	if err := c.validateOutboundURL(ctx, targetURL, c.baseURL, false, requestKindRegistry); err != nil {
		return nil, err
	}

	response, err := c.executeRequest(ctx, method, targetURL, accept, "")
	if err != nil {
		return nil, fmt.Errorf("perform registry request: %w", err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		return c.checkResponse(response)
	}

	challenge, err := parseBearerChallenge(response.Header.Get("Www-Authenticate"))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if challenge.Scope == "" && repository != "" {
		challenge.Scope = "repository:" + repository + ":pull"
	}
	if challenge.Realm == "" && c.authURL != nil {
		challenge.Realm = c.authURL.String()
	}
	if err := c.validateAuthRealm(ctx, challenge.Realm); err != nil {
		return nil, fmt.Errorf("reject auth realm: %w", err)
	}

	token, err := c.fetchToken(ctx, challenge, true)
	if err != nil {
		return nil, err
	}

	retryResponse, err := c.executeRequest(ctx, method, targetURL, accept, token)
	if err != nil {
		return nil, fmt.Errorf("perform authorized registry request: %w", err)
	}
	if retryResponse.StatusCode == http.StatusUnauthorized {
		retryResponse.Body.Close()
		c.invalidateToken(challenge)

		token, err = c.fetchToken(ctx, challenge, false)
		if err != nil {
			return nil, err
		}

		retryResponse, err = c.executeRequest(ctx, method, targetURL, accept, token)
		if err != nil {
			return nil, fmt.Errorf("perform refreshed authorized registry request: %w", err)
		}
	}

	return c.checkResponse(retryResponse)
}

func (c *Client) checkResponse(response *http.Response) (*http.Response, error) {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response, nil
	}

	defer response.Body.Close()
	return nil, fmt.Errorf("registry request failed: status=%d %s", response.StatusCode, http.StatusText(response.StatusCode))
}

func (c *Client) executeRequest(ctx context.Context, method, targetURL, accept, token string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < c.requestAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create registry request: %w", err)
		}
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		if strings.TrimSpace(token) != "" {
			request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
		}

		response, err := c.doHTTP(request)
		if err != nil {
			lastErr = err
			if attempt+1 < c.requestAttempts && isRetryableRequestError(ctx, err) {
				continue
			}
			return nil, err
		}
		if attempt+1 < c.requestAttempts && isRetryableStatus(response.StatusCode) {
			response.Body.Close()
			lastErr = fmt.Errorf("transient registry status %d", response.StatusCode)
			continue
		}
		return response, nil
	}

	return nil, lastErr
}

func (c *Client) fetchToken(ctx context.Context, challenge bearerChallenge, allowCache bool) (string, error) {
	cacheKey := challenge.cacheKey()
	if allowCache {
		c.tokenCacheMu.Lock()
		if token, ok := c.tokenCache[cacheKey]; ok && token != "" {
			c.tokenCacheMu.Unlock()
			return token, nil
		}
		c.tokenCacheMu.Unlock()
	}
	if err := c.checkTokenCacheAdmission(cacheKey); err != nil {
		return "", err
	}

	realmURL := strings.TrimSpace(challenge.Realm)
	if realmURL == "" {
		return "", fmt.Errorf("bearer auth challenge is missing realm")
	}
	requestCtx, cancel := c.withRequestTimeout(ctx)
	defer cancel()

	parsedRealm, err := url.Parse(realmURL)
	if err != nil {
		return "", fmt.Errorf("auth realm is invalid")
	}
	query := parsedRealm.Query()
	if strings.TrimSpace(challenge.Service) != "" {
		query.Set("service", strings.TrimSpace(challenge.Service))
	}
	if strings.TrimSpace(challenge.Scope) != "" {
		query.Set("scope", strings.TrimSpace(challenge.Scope))
	}
	parsedRealm.RawQuery = query.Encode()
	if err := c.validateAuthRealm(requestCtx, parsedRealm.String()); err != nil {
		return "", fmt.Errorf("reject auth realm: %w", err)
	}
	requestCtx = context.WithValue(requestCtx, requestKindContextKey{}, requestKindAuth)

	response, err := c.executeRequest(requestCtx, http.MethodGet, parsedRealm.String(), "", "")
	if err != nil {
		return "", fmt.Errorf("perform auth request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("auth request failed: status=%d %s", response.StatusCode, http.StatusText(response.StatusCode))
	}

	maxAuthResponseBytes := c.maxAuthResponseBytes
	if maxAuthResponseBytes <= 0 {
		maxAuthResponseBytes = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limits.OverflowProbeLimit(maxAuthResponseBytes)))
	if err != nil {
		return "", fmt.Errorf("read auth token response: %w", err)
	}
	if int64(len(body)) > maxAuthResponseBytes {
		return "", limits.NewExceeded(limits.Kind("auth_response_bytes"), maxAuthResponseBytes, "auth token response")
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode auth token response: %w", err)
	}

	token := firstNonEmpty(payload.Token, payload.AccessToken)
	if token == "" {
		return "", fmt.Errorf("auth token response did not include a token")
	}

	if err := c.cacheToken(cacheKey, token); err != nil {
		return "", err
	}

	return token, nil
}

func (c *Client) withRequestTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.requestTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.requestTimeout)
}

func (c *Client) invalidateToken(challenge bearerChallenge) {
	cacheKey := challenge.cacheKey()
	c.tokenCacheMu.Lock()
	if token, ok := c.tokenCache[cacheKey]; ok {
		c.tokenCacheBytes -= len(cacheKey) + len(token)
	}
	delete(c.tokenCache, cacheKey)
	c.tokenCacheMu.Unlock()
}

func (c *Client) checkTokenCacheAdmission(cacheKey string) error {
	c.tokenCacheMu.Lock()
	defer c.tokenCacheMu.Unlock()

	if _, ok := c.tokenCache[cacheKey]; ok {
		return nil
	}
	if len(c.tokenCache) >= maxTokenCacheEntries {
		return limits.NewExceeded(limits.Kind("auth_token_cache_entries"), maxTokenCacheEntries, "auth token cache")
	}
	if len(cacheKey) >= maxTokenCacheBytes-c.tokenCacheBytes {
		return limits.NewExceeded(limits.Kind("auth_token_cache_bytes"), maxTokenCacheBytes, "auth token cache")
	}
	return nil
}

func (c *Client) cacheToken(cacheKey, token string) error {
	c.tokenCacheMu.Lock()
	defer c.tokenCacheMu.Unlock()

	previous, exists := c.tokenCache[cacheKey]
	if !exists && len(c.tokenCache) >= maxTokenCacheEntries {
		return limits.NewExceeded(limits.Kind("auth_token_cache_entries"), maxTokenCacheEntries, "auth token cache")
	}

	entryBytes := len(cacheKey) + len(token)
	retainedBytes := c.tokenCacheBytes
	if exists {
		retainedBytes -= len(cacheKey) + len(previous)
	}
	if entryBytes > maxTokenCacheBytes || retainedBytes > maxTokenCacheBytes-entryBytes {
		return limits.NewExceeded(limits.Kind("auth_token_cache_bytes"), maxTokenCacheBytes, "auth token cache")
	}

	if c.tokenCache == nil {
		c.tokenCache = make(map[string]string)
	}
	c.tokenCache[cacheKey] = token
	c.tokenCacheBytes = retainedBytes + entryBytes
	return nil
}

func parseBearerChallenge(header string) (bearerChallenge, error) {
	value := strings.TrimSpace(header)
	if value == "" {
		return bearerChallenge{}, fmt.Errorf("registry auth challenge is missing")
	}
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return bearerChallenge{}, fmt.Errorf("unsupported registry auth challenge")
	}

	value = strings.TrimSpace(value[len("Bearer "):])
	pieces := strings.Split(value, ",")
	challenge := bearerChallenge{}
	for _, piece := range pieces {
		item := strings.TrimSpace(piece)
		if item == "" {
			continue
		}
		key, rawValue, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rawValue = strings.TrimSpace(strings.Trim(rawValue, `"`))
		switch key {
		case "realm":
			challenge.Realm = rawValue
		case "service":
			challenge.Service = rawValue
		case "scope":
			challenge.Scope = rawValue
		}
	}

	if challenge.Realm == "" {
		return bearerChallenge{}, fmt.Errorf("bearer auth challenge did not include a realm")
	}

	return challenge, nil
}

func (c *Client) join(parts ...string) string {
	if c.baseURL == nil {
		return ""
	}

	value := *c.baseURL
	segments := make([]string, 0, len(parts)+1)
	if trimmed := strings.Trim(value.Path, "/"); trimmed != "" {
		segments = append(segments, trimmed)
	}
	segments = append(segments, parts...)
	value.Path = "/" + path.Join(segments...)

	return value.String()
}

func (b bearerChallenge) cacheKey() string {
	return strings.Join([]string{b.Realm, b.Service, b.Scope}, "|")
}

func isValidTag(tag string) bool {
	return tag != "" && distributionreference.TagRegexp.FindString(tag) == tag
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isRetryableRequestError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return true
	}

	return false
}

func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return statusCode >= 500 && statusCode <= 599
	}
}

func appendURLQuery(targetURL string, values map[string]string) (string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("url is invalid")
	}

	query := parsed.Query()
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		query.Set(key, strings.TrimSpace(value))
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func readManifestBody(reader io.Reader, maxBytes int64, identifier string) ([]byte, error) {
	if maxBytes <= 0 {
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read manifest response: %w", err)
		}
		return body, nil
	}

	limited := io.LimitReader(reader, limits.OverflowProbeLimit(maxBytes))
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read manifest response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, limits.NewExceeded(limits.KindManifestBytes, maxBytes, "manifest "+strings.TrimSpace(identifier))
	}

	return body, nil
}

func readTagResponseBody(reader io.Reader, maxBytes int64, repository string) ([]byte, error) {
	if maxBytes <= 0 {
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read tags response: %w", err)
		}
		return body, nil
	}

	limited := io.LimitReader(reader, limits.OverflowProbeLimit(maxBytes))
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read tags response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, limits.NewExceeded(limits.KindTagResponseBytes, maxBytes, "tag response for repository "+strings.TrimSpace(repository))
	}

	return body, nil
}

func nextLinkURL(currentURL, header string) (string, bool, error) {
	value := strings.TrimSpace(header)
	if value == "" {
		return "", false, nil
	}

	parts := strings.Split(value, ";")
	if len(parts) == 0 {
		return "", false, fmt.Errorf("parse link header: missing link target")
	}
	if len(parts) > 1 && !strings.EqualFold(strings.TrimSpace(parts[1]), `rel="next"`) {
		return "", false, nil
	}

	target := strings.TrimSpace(parts[0])
	target = strings.TrimPrefix(target, "<")
	target = strings.TrimSuffix(target, ">")
	if target == "" {
		return "", false, fmt.Errorf("parse link header: missing url")
	}

	parsedCurrent, err := url.Parse(currentURL)
	if err != nil {
		return "", false, fmt.Errorf("current pagination url is invalid")
	}
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return "", false, fmt.Errorf("pagination link url is invalid")
	}
	return parsedCurrent.ResolveReference(parsedTarget).String(), true, nil
}

func (c *Client) nextLinkURL(ctx context.Context, currentURL, header string) (string, bool, error) {
	nextURL, ok, err := nextLinkURL(currentURL, header)
	if err != nil || !ok {
		return nextURL, ok, err
	}
	current, err := url.Parse(currentURL)
	if err != nil {
		return "", false, fmt.Errorf("current pagination url is invalid")
	}
	if err := c.validateOutboundURL(ctx, nextURL, current, false, requestKindRegistry); err != nil {
		return "", false, fmt.Errorf("reject pagination link: %w", err)
	}
	return nextURL, true, nil
}

func (c *Client) doHTTP(request *http.Request) (*http.Response, error) {
	client := *c.httpClient
	requestKind := requestKindFromContext(request.Context())
	configuredRedirect := c.httpClient.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return fmt.Errorf("redirect has no origin request")
		}
		if len(via) > c.maxRedirects {
			return fmt.Errorf("stopped after %d redirects", c.maxRedirects)
		}
		if configuredRedirect != nil {
			if err := configuredRedirect(next, via); err != nil {
				return err
			}
		}
		origin := via[0].URL
		if err := c.validateOutboundURL(next.Context(), next.URL.String(), origin, true, requestKind); err != nil {
			return fmt.Errorf("reject redirect: %w", err)
		}
		if !sameURLHost(via[len(via)-1].URL, next.URL) {
			next.Header.Del("Authorization")
		}
		return nil
	}

	return client.Do(request)
}

func parseEndpointURL(value string, allowHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("endpoint url is invalid")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("endpoint url must be absolute and must not include userinfo or fragment")
	}
	if !validAllowedHostname(parsed.Hostname()) {
		return nil, fmt.Errorf("endpoint url host is invalid")
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.Atoi(port)
		if portErr != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("endpoint url port is invalid")
		}
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return nil, fmt.Errorf("endpoint url must use https")
	}
	return parsed, nil
}

func parseConfiguredEndpointURL(value string, allowHTTP bool) (*url.URL, error) {
	parsed, err := parseEndpointURL(value, allowHTTP)
	if err != nil {
		return nil, err
	}
	if parsed.RawQuery != "" {
		return nil, fmt.Errorf("configured endpoint url must not include a query")
	}
	return parsed, nil
}

type outboundRequestKind string

const (
	requestKindRegistry outboundRequestKind = "registry"
	requestKindAuth     outboundRequestKind = "auth"
)

type requestKindContextKey struct{}

func requestKindFromContext(ctx context.Context) outboundRequestKind {
	if ctx != nil {
		if kind, ok := ctx.Value(requestKindContextKey{}).(outboundRequestKind); ok && kind == requestKindAuth {
			return kind
		}
	}
	return requestKindRegistry
}

func (c *Client) validateOutboundURL(ctx context.Context, value string, origin *url.URL, allowCrossHost bool, kind outboundRequestKind) error {
	parsed, err := parseEndpointURL(value, true)
	if err != nil {
		return err
	}
	if origin != nil && !allowCrossHost && !sameURLHost(origin, parsed) {
		return fmt.Errorf("cross-host request to %s is not allowed", parsed.Host)
	}
	if parsed.Scheme == "http" && !c.hostAllowed(parsed, kind) {
		return fmt.Errorf("http is allowed only for an explicitly allowlisted private %s host", kind)
	}
	_, err = c.resolveOutbound(ctx, parsed, kind)
	return err
}

func (c *Client) resolveOutbound(ctx context.Context, parsed *url.URL, kind outboundRequestKind) ([]net.IPAddr, error) {
	if c.allowPrivateHosts || c.lookupIP == nil {
		return nil, nil
	}
	host := parsed.Hostname()
	addresses, err := c.lookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s host %s: %w", kind, host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s host %s did not resolve", kind, host)
	}
	if !c.hostAllowed(parsed, kind) {
		for _, address := range addresses {
			if isNonPublicAddress(address.IP) {
				return nil, fmt.Errorf("non-public %s address %s is not allowed", kind, address.IP)
			}
		}
	}
	return addresses, nil
}

func (c *Client) validateAuthRealm(ctx context.Context, value string) error {
	parsed, err := parseEndpointURL(value, true)
	if err != nil {
		return err
	}
	return c.validateOutboundURL(ctx, parsed.String(), c.baseURL, true, requestKindAuth)
}

func (c *Client) hostAllowed(value *url.URL, kind outboundRequestKind) bool {
	allowed := c.allowedPrivateRegistryHosts
	if kind == requestKindAuth {
		allowed = c.allowedPrivateAuthHosts
	}
	_, ok := allowed[canonicalURLHost(value)]
	return ok
}

func (c *Client) validateConfiguredEndpointSchemes() {
	if c.baseURL != nil && c.baseURL.Scheme == "http" && !c.hostAllowed(c.baseURL, requestKindRegistry) {
		c.configErr = errors.Join(c.configErr, fmt.Errorf("http registry endpoint %s must be explicitly allowlisted", c.baseURL.Host))
	}
	if c.authURL != nil && c.authURL.Scheme == "http" && !c.hostAllowed(c.authURL, requestKindAuth) {
		c.configErr = errors.Join(c.configErr, fmt.Errorf("http auth endpoint %s must be explicitly allowlisted", c.authURL.Host))
	}
}

func normalizeHostAllowlist(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	var joined error
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || strings.ContainsAny(value, `/@*?#`) || strings.Contains(value, "://") {
			joined = errors.Join(joined, fmt.Errorf("invalid allowed private host %q", raw))
			continue
		}
		parsed, err := url.Parse("https://" + value)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			joined = errors.Join(joined, fmt.Errorf("invalid allowed private host %q", raw))
			continue
		}
		if port := parsed.Port(); port != "" {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				joined = errors.Join(joined, fmt.Errorf("invalid allowed private host %q", raw))
				continue
			}
		}
		if strings.Contains(parsed.Hostname(), ":") && !strings.HasPrefix(value, "[") {
			joined = errors.Join(joined, fmt.Errorf("IPv6 allowed private host %q must use brackets", raw))
			continue
		}
		if !validAllowedHostname(parsed.Hostname()) {
			joined = errors.Join(joined, fmt.Errorf("invalid allowed private host %q", raw))
			continue
		}
		result[canonicalURLHost(parsed)] = struct{}{}
	}
	return result, joined
}

func validAllowedHostname(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if net.ParseIP(value) != nil {
		return true
	}
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func canonicalURLHost(value *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if value.Port() == "" {
		return host
	}
	return net.JoinHostPort(host, value.Port())
}

func (c *Client) hardenHTTPClient() {
	if c.httpClient == nil || c.allowPrivateHosts {
		return
	}
	client := *c.httpClient
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		c.configErr = errors.Join(c.configErr, fmt.Errorf("custom registry transport requires explicit AllowPrivateHosts test override"))
		return
	}
	if base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		c.configErr = errors.Join(c.configErr, fmt.Errorf("registry transport must verify TLS certificates"))
		return
	}
	hardenedTransport := base.Clone()
	if hardenedTransport.TLSClientConfig == nil {
		hardenedTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if hardenedTransport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		hardenedTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	if hardenedTransport.MaxResponseHeaderBytes <= 0 || hardenedTransport.MaxResponseHeaderBytes > maxRegistryResponseHeaderBytes {
		hardenedTransport.MaxResponseHeaderBytes = maxRegistryResponseHeaderBytes
	}
	client.Transport = &pinnedTransport{base: hardenedTransport, client: c}
	c.httpClient = &client
}

type pinnedTransport struct {
	base   *http.Transport
	client *Client
}

func (t *pinnedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	kind := requestKindFromContext(request.Context())
	addresses, err := t.client.resolveOutbound(request.Context(), request.URL, kind)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s host %s did not resolve", kind, request.URL.Hostname())
	}

	originalRequest := request
	request = request.Clone(request.Context())
	request.URL = cloneURL(originalRequest.URL)
	request.Host = originalRequest.URL.Host
	port := originalRequest.URL.Port()
	if port == "" {
		port = effectivePort(originalRequest.URL)
	}
	request.URL.Host = net.JoinHostPort(addresses[0].IP.String(), port)

	transport := t.base.Clone()
	transport.DisableKeepAlives = true
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	tlsConfig := transport.TLSClientConfig.Clone()
	tlsConfig.ServerName = originalRequest.URL.Hostname()
	transport.TLSClientConfig = tlsConfig
	if t.base.Proxy != nil {
		proxyURL, proxyErr := t.base.Proxy(originalRequest)
		if proxyErr != nil {
			return nil, proxyErr
		}
		transport.Proxy = func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	}

	response, err := transport.RoundTrip(request)
	if response != nil {
		response.Request = originalRequest
	}
	return response, err
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return new(url.URL)
	}
	cloned := *value
	return &cloned
}

func sameURLHost(left, right *url.URL) bool {
	return strings.EqualFold(left.Hostname(), right.Hostname()) && effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "https" {
		return "443"
	}
	if value.Scheme == "http" {
		return "80"
	}
	return ""
}

var nonPublicAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isNonPublicAddress(value net.IP) bool {
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range nonPublicAddressPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
