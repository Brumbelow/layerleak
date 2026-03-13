package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
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

func (c *Client) doRequest(ctx context.Context, method, targetURL, accept, repository string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	request, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create registry request: %w", err)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}

	response, err := c.httpClient.Do(request)
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

	token, err := c.fetchToken(ctx, challenge)
	if err != nil {
		return nil, err
	}

	retryRequest, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create registry retry request: %w", err)
	}
	if accept != "" {
		retryRequest.Header.Set("Accept", accept)
	}
	retryRequest.Header.Set("Authorization", "Bearer "+token)

	retryResponse, err := c.httpClient.Do(retryRequest)
	if err != nil {
		return nil, fmt.Errorf("perform authorized registry request: %w", err)
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

func (c *Client) fetchToken(ctx context.Context, challenge bearerChallenge) (string, error) {
	cacheKey := challenge.cacheKey()
	c.tokenCacheMu.Lock()
	if token, ok := c.tokenCache[cacheKey]; ok && token != "" {
		c.tokenCacheMu.Unlock()
		return token, nil
	}
	c.tokenCacheMu.Unlock()

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

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedRealm.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create auth request: %w", err)
	}

	response, err := c.httpClient.Do(request)
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
