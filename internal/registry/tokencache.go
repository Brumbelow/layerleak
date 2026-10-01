package registry

import (
	"strings"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/limits"
)

const (
	maxTokenCacheEntries = 128
	maxTokenCacheBytes   = 1 << 20
	// defaultTokenLifetime applies when the token endpoint does not advertise
	// expires_in; the distribution token specification documents 60 seconds.
	defaultTokenLifetime = 60 * time.Second
	// tokenExpirySafetyMargin is subtracted from the advertised lifetime so a
	// token is refreshed before the registry starts rejecting it.
	tokenExpirySafetyMargin = 10 * time.Second
	// maxTokenLifetime caps the advertised lifetime: expires_in is hostile
	// input and an absurd value must neither overflow the duration arithmetic
	// nor keep a token alive for the whole process lifetime.
	maxTokenLifetime = 24 * time.Hour
)

// tokenCacheEntry is one cached bearer token. The cache lives inside the
// Client and is dropped with it; it is never persisted.
type tokenCacheEntry struct {
	token     string
	expiresAt time.Time
}

// tokenCacheKey scopes a cached token to the registry host, the challenge
// (realm, service and scope, which names the repository) and the identity that
// obtained it, so anonymous and authenticated tokens, or tokens of two users,
// never mix.
func (c *Client) tokenCacheKey(challenge bearerChallenge, credential Credential) string {
	registryHost := ""
	if c.baseURL != nil {
		registryHost = canonicalURLHost(c.baseURL)
	}
	return strings.Join([]string{registryHost, challenge.Realm, challenge.Service, challenge.Scope, credential.identity()}, "|")
}

// tokenExpiry converts the advertised expires_in (seconds) into an absolute
// deadline, applying the default lifetime when it is absent or negative, the
// 24-hour cap, and the safety margin. A lifetime at or below the margin yields
// a deadline in the past, so such a token is used once and never cached.
func (c *Client) tokenExpiry(expiresIn int64) time.Time {
	lifetime := defaultTokenLifetime
	if expiresIn > 0 {
		if expiresIn > int64(maxTokenLifetime/time.Second) {
			lifetime = maxTokenLifetime
		} else {
			lifetime = time.Duration(expiresIn) * time.Second
		}
	}
	return c.now().Add(lifetime - tokenExpirySafetyMargin)
}

// cachedToken returns the live token for cacheKey. An expired entry is
// evicted and reported as a miss.
func (c *Client) cachedToken(cacheKey string) (string, bool) {
	c.tokenCacheMu.Lock()
	defer c.tokenCacheMu.Unlock()

	entry, ok := c.tokenCache[cacheKey]
	if !ok || entry.token == "" {
		return "", false
	}
	if !entry.expiresAt.IsZero() && !c.now().Before(entry.expiresAt) {
		c.removeTokenLocked(cacheKey)
		return "", false
	}
	return entry.token, true
}

func (c *Client) invalidateToken(cacheKey string) {
	c.tokenCacheMu.Lock()
	c.removeTokenLocked(cacheKey)
	c.tokenCacheMu.Unlock()
}

func (c *Client) removeTokenLocked(cacheKey string) {
	if entry, ok := c.tokenCache[cacheKey]; ok {
		c.tokenCacheBytes -= len(cacheKey) + len(entry.token)
	}
	delete(c.tokenCache, cacheKey)
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

// cacheToken stores token under cacheKey until expiresAt. A deadline that has
// already passed is not stored. The entry and byte limits fail closed: a
// client that has filled its cache stops rather than growing unbounded.
func (c *Client) cacheToken(cacheKey, token string, expiresAt time.Time) error {
	if !expiresAt.IsZero() && !c.now().Before(expiresAt) {
		return nil
	}
	c.tokenCacheMu.Lock()
	defer c.tokenCacheMu.Unlock()

	previous, exists := c.tokenCache[cacheKey]
	if !exists && len(c.tokenCache) >= maxTokenCacheEntries {
		return limits.NewExceeded(limits.Kind("auth_token_cache_entries"), maxTokenCacheEntries, "auth token cache")
	}

	entryBytes := len(cacheKey) + len(token)
	retainedBytes := c.tokenCacheBytes
	if exists {
		retainedBytes -= len(cacheKey) + len(previous.token)
	}
	if entryBytes > maxTokenCacheBytes || retainedBytes > maxTokenCacheBytes-entryBytes {
		return limits.NewExceeded(limits.Kind("auth_token_cache_bytes"), maxTokenCacheBytes, "auth token cache")
	}

	if c.tokenCache == nil {
		c.tokenCache = make(map[string]tokenCacheEntry)
	}
	c.tokenCache[cacheKey] = tokenCacheEntry{token: token, expiresAt: expiresAt}
	c.tokenCacheBytes = retainedBytes + entryBytes
	return nil
}
