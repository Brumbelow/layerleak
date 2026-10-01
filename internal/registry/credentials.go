package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// dockerHubLookupHost is the lookup key every spelling of Docker Hub
// (docker.io, index.docker.io, registry-1.docker.io and the legacy
// https://index.docker.io/v1/ Docker config key) normalizes to.
const dockerHubLookupHost = "index.docker.io"

// ErrCredentialsRequireHTTPS is returned when a credential exists for a
// registry or token endpoint that is reached over plain http. Credentials are
// never sent in clear, even to an allowlisted private host.
var ErrCredentialsRequireHTTPS = errors.New("registry credentials are only sent over https")

// Credential is a username and password for one registry host. Its String and
// GoString methods redact both fields so formatting an Options value, a
// CredentialSource or an error that embeds a Credential never reveals them.
type Credential struct {
	Username string
	Password string
}

// IsZero reports whether the credential carries neither a username nor a
// password.
func (c Credential) IsZero() bool {
	return c.Username == "" && c.Password == ""
}

// String redacts the credential.
func (c Credential) String() string {
	return "registry.Credential{redacted}"
}

// GoString redacts the credential for %#v.
func (c Credential) GoString() string {
	return c.String()
}

// identity is a short, stable digest of the credential that scopes token-cache
// entries to the identity that obtained them. It cannot be inverted into the
// password and is not logged.
func (c Credential) identity() string {
	if c.IsZero() {
		return "anonymous"
	}
	sum := sha256.Sum256([]byte(c.Username + "\x00" + c.Password))
	return hex.EncodeToString(sum[:8])
}

// basicAuthorization is the Authorization header value for the credential.
func (c Credential) basicAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
}

// CredentialSource resolves the credential for a registry host. host is the
// `host` or `host:port` the client is about to contact (Docker Hub is looked
// up as index.docker.io whichever alias was used). ok is false when the source
// has nothing for the host; an error means the source could not decide (for
// example an unreadable Docker config or an entry that needs a credential
// helper) and aborts the request rather than silently falling back to
// anonymous access.
type CredentialSource interface {
	Lookup(ctx context.Context, host string) (credential Credential, ok bool, err error)
}

// StaticCredentials binds one username and password to one registry host. The
// host may be given as a registry name (docker.io, ghcr.io, localhost:5000) or
// as a URL; only requests to that host receive the credential.
func StaticCredentials(host, username, password string) CredentialSource {
	return &staticCredentials{
		host:       normalizeCredentialHost(host),
		credential: Credential{Username: username, Password: password},
	}
}

type staticCredentials struct {
	host       string
	credential Credential
}

func (s *staticCredentials) Lookup(_ context.Context, host string) (Credential, bool, error) {
	if s == nil || s.host == "" || s.credential.IsZero() {
		return Credential{}, false, nil
	}
	if normalizeCredentialHost(host) != s.host {
		return Credential{}, false, nil
	}
	return s.credential, true, nil
}

// String names the bound host and redacts the credential.
func (s *staticCredentials) String() string {
	if s == nil {
		return "registry.StaticCredentials(nil)"
	}
	return fmt.Sprintf("registry.StaticCredentials{host:%s credential:redacted}", s.host)
}

// GoString redacts the credential for %#v.
func (s *staticCredentials) GoString() string {
	return s.String()
}

// ChainCredentials consults the sources in order and returns the first
// credential found. nil sources are skipped. An error from a source stops the
// chain, so an unsupported Docker credential helper is reported instead of
// being masked by a later anonymous fallback.
func ChainCredentials(sources ...CredentialSource) CredentialSource {
	chain := make(chainCredentials, 0, len(sources))
	for _, source := range sources {
		if source == nil {
			continue
		}
		chain = append(chain, source)
	}
	return chain
}

type chainCredentials []CredentialSource

func (c chainCredentials) Lookup(ctx context.Context, host string) (Credential, bool, error) {
	for _, source := range c {
		credential, ok, err := source.Lookup(ctx, host)
		if err != nil {
			return Credential{}, false, err
		}
		if ok {
			return credential, true, nil
		}
	}
	return Credential{}, false, nil
}

// String lists the chained sources; each redacts its own credential.
func (c chainCredentials) String() string {
	parts := make([]string, 0, len(c))
	for _, source := range c {
		parts = append(parts, fmt.Sprint(source))
	}
	return "registry.ChainCredentials[" + strings.Join(parts, ", ") + "]"
}

// GoString redacts the chained credentials for %#v.
func (c chainCredentials) GoString() string {
	return c.String()
}

// normalizeCredentialHost reduces a registry name, URL or Docker config key to
// the lookup key: lower-case `host` or `host:port` without scheme, path,
// userinfo or trailing dot, with every Docker Hub alias mapped to
// index.docker.io. Unparseable input normalizes to "" and never matches.
func normalizeCredentialHost(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, "://"); index >= 0 {
		value = value[index+3:]
	}
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		value = value[:index]
	}
	if index := strings.LastIndex(value, "@"); index >= 0 {
		value = value[index+1:]
	}
	if value == "" {
		return ""
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	host := canonicalURLHost(parsed)
	switch host {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return dockerHubLookupHost
	}
	return host
}
