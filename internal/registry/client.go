package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/brumbelow/layerleak/internal/manifest"
)

type Options struct {
	BaseURL    string
	AuthURL    string
	HTTPClient *http.Client
}

type Client struct {
	baseURL      *url.URL
	authURL      *url.URL
	httpClient   *http.Client
	tokenCache   map[string]string
	tokenCacheMu sync.Mutex
}

type ManifestResponse struct {
	Digest    string
	MediaType string
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

const requestAttempts = 2

func NewClient(options Options) *Client {
	baseURL, _ := url.Parse(defaultString(options.BaseURL, "https://registry-1.docker.io"))
	authURL, _ := url.Parse(defaultString(options.AuthURL, "https://auth.docker.io/token"))
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Client{
		baseURL:    baseURL,
		authURL:    authURL,
		httpClient: httpClient,
		tokenCache: make(map[string]string),
	}
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
	response, err := c.doRequest(ctx, http.MethodGet, c.ManifestURL(repository, identifier), strings.Join([]string{
		manifest.MediaTypeOCIImageIndex,
		manifest.MediaTypeOCIImageManifest,
		manifest.MediaTypeDockerSchema2ManifestList,
		manifest.MediaTypeDockerSchema2Manifest,
	}, ", "), repository)
	if err != nil {
		return ManifestResponse{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return ManifestResponse{}, fmt.Errorf("read manifest response: %w", err)
	}

	return ManifestResponse{
		Digest:    strings.TrimSpace(response.Header.Get("Docker-Content-Digest")),
		MediaType: strings.TrimSpace(response.Header.Get("Content-Type")),
		Body:      body,
	}, nil
}

func (c *Client) ResolveManifest(ctx context.Context, repository, identifier string) (ManifestMetadata, error) {
	response, err := c.doRequest(ctx, http.MethodHead, c.ManifestURL(repository, identifier), strings.Join([]string{
		manifest.MediaTypeOCIImageIndex,
		manifest.MediaTypeOCIImageManifest,
		manifest.MediaTypeDockerSchema2ManifestList,
		manifest.MediaTypeDockerSchema2Manifest,
	}, ", "), repository)
	if err == nil {
		response.Body.Close()
		resolved := ManifestMetadata{
			Digest:    strings.TrimSpace(response.Header.Get("Docker-Content-Digest")),
			MediaType: strings.TrimSpace(response.Header.Get("Content-Type")),
		}
		if resolved.Digest != "" {
			return resolved, nil
		}
	}

	manifestResponse, err := c.FetchManifest(ctx, repository, identifier)
	if err != nil {
		return ManifestMetadata{}, err
	}

	return ManifestMetadata{
		Digest:    manifestResponse.Digest,
		MediaType: manifestResponse.MediaType,
	}, nil
}

func (c *Client) OpenBlob(ctx context.Context, repository, digest string) (BlobResponse, error) {
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

func (c *Client) ListTags(ctx context.Context, repository string, pageSize int) ([]string, error) {
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
	tags := make([]string, 0)
	for {
		response, err := c.doRequest(ctx, http.MethodGet, targetURL, "application/json", repository)
		if err != nil {
			return nil, err
		}

		var payload struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&payload)
		linkHeader := response.Header.Get("Link")
		response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode tags response: %w", decodeErr)
		}

		for _, tag := range payload.Tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}

		nextURL, ok, err := nextLinkURL(targetURL, linkHeader)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
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
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return nil, fmt.Errorf("registry request failed: status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
}

func (c *Client) executeRequest(ctx context.Context, method, targetURL, accept, token string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < requestAttempts; attempt++ {
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

		response, err := c.httpClient.Do(request)
		if err != nil {
			lastErr = err
			if attempt+1 < requestAttempts && isRetryableRequestError(ctx, err) {
				continue
			}
			return nil, err
		}
		if attempt+1 < requestAttempts && isRetryableStatus(response.StatusCode) {
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

	realmURL := strings.TrimSpace(challenge.Realm)
	if realmURL == "" {
		return "", fmt.Errorf("bearer auth challenge is missing realm")
	}

	parsedRealm, err := url.Parse(realmURL)
	if err != nil {
		return "", fmt.Errorf("parse auth realm: %w", err)
	}
	query := parsedRealm.Query()
	if strings.TrimSpace(challenge.Service) != "" {
		query.Set("service", strings.TrimSpace(challenge.Service))
	}
	if strings.TrimSpace(challenge.Scope) != "" {
		query.Set("scope", strings.TrimSpace(challenge.Scope))
	}
	parsedRealm.RawQuery = query.Encode()

	response, err := c.executeRequest(ctx, http.MethodGet, parsedRealm.String(), "", "")
	if err != nil {
		return "", fmt.Errorf("perform auth request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("auth request failed: status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode auth token response: %w", err)
	}

	token := firstNonEmpty(payload.Token, payload.AccessToken)
	if token == "" {
		return "", fmt.Errorf("auth token response did not include a token")
	}

	c.tokenCacheMu.Lock()
	c.tokenCache[cacheKey] = token
	c.tokenCacheMu.Unlock()

	return token, nil
}

func (c *Client) invalidateToken(challenge bearerChallenge) {
	cacheKey := challenge.cacheKey()
	c.tokenCacheMu.Lock()
	delete(c.tokenCache, cacheKey)
	c.tokenCacheMu.Unlock()
}

func parseBearerChallenge(header string) (bearerChallenge, error) {
	value := strings.TrimSpace(header)
	if value == "" {
		return bearerChallenge{}, fmt.Errorf("registry auth challenge is missing")
	}
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return bearerChallenge{}, fmt.Errorf("unsupported auth challenge: %s", value)
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
		return "", fmt.Errorf("parse url %q: %w", targetURL, err)
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
		return "", false, fmt.Errorf("parse current url: %w", err)
	}
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return "", false, fmt.Errorf("parse next link url: %w", err)
	}
	return parsedCurrent.ResolveReference(parsedTarget).String(), true, nil
}
