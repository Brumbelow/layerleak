package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/brumbelow/layerleak/v3/internal/limits"
)

// maxDockerConfigBytes bounds the Docker config.json read. A real file is a
// few kilobytes; anything larger is refused rather than buffered.
const maxDockerConfigBytes = 1 << 20

// UnsupportedCredentialError reports a Docker config entry for the host that
// exists but needs a mechanism Layerleak does not implement: a credential
// helper (credHelpers), a credential store (credsStore) or an identity token.
// Error never includes the credential material.
type UnsupportedCredentialError struct {
	Host      string
	Mechanism string
}

func (e *UnsupportedCredentialError) Error() string {
	return fmt.Sprintf("docker config entry for %s uses %s, which layerleak does not support; supply the username and password directly", e.Host, e.Mechanism)
}

// DockerConfigCredentials reads the `auths` map of a Docker `config.json` at
// path. Entries may carry a base64 `auth` field (`username:password`) or
// separate `username` and `password` fields; keys may be bare hosts, URLs or
// the legacy `https://index.docker.io/v1/` Docker Hub key. Credential helpers
// (`credsStore`, `credHelpers`) are not invoked: a host they cover is reported
// through *UnsupportedCredentialError. The file is read once, on the first
// lookup, and must be at most 1 MiB.
func DockerConfigCredentials(path string) CredentialSource {
	return &dockerConfigSource{path: path}
}

type dockerConfigSource struct {
	path   string
	once   sync.Once
	config *parsedDockerConfig
	err    error
}

type dockerConfigFile struct {
	Auths       map[string]dockerAuthEntry `json:"auths"`
	CredsStore  string                     `json:"credsStore"`
	CredHelpers map[string]string          `json:"credHelpers"`
}

type dockerAuthEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// parsedDockerConfig holds the normalized view of a config file: credentials
// and placeholder entries by normalized host, plus the helper configuration.
type parsedDockerConfig struct {
	credentials map[string]Credential
	placeholder map[string]bool
	credsStore  string
	credHelpers map[string]string
}

func (s *dockerConfigSource) Lookup(_ context.Context, host string) (Credential, bool, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return Credential{}, false, nil
	}
	s.once.Do(func() {
		s.config, s.err = loadDockerConfig(s.path)
	})
	if s.err != nil {
		return Credential{}, false, s.err
	}
	return s.config.lookup(normalizeCredentialHost(host))
}

// String names the file and never its contents.
func (s *dockerConfigSource) String() string {
	if s == nil {
		return "registry.DockerConfigCredentials(nil)"
	}
	return fmt.Sprintf("registry.DockerConfigCredentials{path:%s}", s.path)
}

// GoString redacts the parsed credentials for %#v.
func (s *dockerConfigSource) GoString() string {
	return s.String()
}

func (p *parsedDockerConfig) lookup(host string) (Credential, bool, error) {
	if host == "" {
		return Credential{}, false, nil
	}
	if helper, ok := p.credHelpers[host]; ok {
		return Credential{}, false, &UnsupportedCredentialError{Host: host, Mechanism: "credential helper " + helper}
	}
	if credential, ok := p.credentials[host]; ok {
		return credential, true, nil
	}
	if p.placeholder[host] && p.credsStore != "" {
		return Credential{}, false, &UnsupportedCredentialError{Host: host, Mechanism: "credential store " + p.credsStore}
	}
	return Credential{}, false, nil
}

func loadDockerConfig(path string) (*parsedDockerConfig, error) {
	file, err := os.Open(path) //nolint:gosec // the path is operator configuration (LAYERLEAK_DOCKER_CONFIG), validated at load
	if err != nil {
		return nil, fmt.Errorf("read docker config: %w", err)
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, limits.OverflowProbeLimit(maxDockerConfigBytes)))
	if err != nil {
		return nil, fmt.Errorf("read docker config %s: %w", path, err)
	}
	if int64(len(body)) > maxDockerConfigBytes {
		return nil, limits.NewExceeded(limits.Kind("docker_config_bytes"), maxDockerConfigBytes, "docker config "+path)
	}
	return parseDockerConfig(body)
}

// parseDockerConfig decodes the file body. Errors name the host of the
// offending entry but never echo field values, because a malformed `auth`
// field is still most likely a password.
func parseDockerConfig(body []byte) (*parsedDockerConfig, error) {
	var file dockerConfigFile
	if err := json.Unmarshal(body, &file); err != nil {
		return nil, errors.New("parse docker config: file is not valid json")
	}
	parsed := &parsedDockerConfig{
		credentials: make(map[string]Credential, len(file.Auths)),
		placeholder: make(map[string]bool),
		credsStore:  strings.TrimSpace(file.CredsStore),
		credHelpers: make(map[string]string, len(file.CredHelpers)),
	}
	for key, helper := range file.CredHelpers {
		host := normalizeCredentialHost(key)
		if host == "" || strings.TrimSpace(helper) == "" {
			continue
		}
		parsed.credHelpers[host] = strings.TrimSpace(helper)
	}
	keys := make([]string, 0, len(file.Auths))
	for key := range file.Auths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var problems error
	for _, key := range keys {
		host := normalizeCredentialHost(key)
		if host == "" {
			problems = errors.Join(problems, fmt.Errorf("docker config auths entry %q has an invalid host", key))
			continue
		}
		entry := file.Auths[key]
		credential, err := entry.credential()
		if err != nil {
			problems = errors.Join(problems, fmt.Errorf("docker config entry for %s: %w", host, err))
			continue
		}
		if credential.IsZero() {
			if strings.TrimSpace(entry.IdentityToken) != "" {
				problems = errors.Join(problems, &UnsupportedCredentialError{Host: host, Mechanism: "an identity token"})
				continue
			}
			parsed.placeholder[host] = true
			continue
		}
		if _, exists := parsed.credentials[host]; !exists {
			parsed.credentials[host] = credential
		}
	}
	if problems != nil {
		return nil, problems
	}
	return parsed, nil
}

// credential decodes one auths entry. The base64 `auth` field wins over the
// plain fields when both are present, matching the Docker CLI.
func (e dockerAuthEntry) credential() (Credential, error) {
	if auth := strings.TrimSpace(e.Auth); auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(auth)
		}
		if err != nil {
			return Credential{}, errors.New("auth field is not valid base64")
		}
		username, password, ok := strings.Cut(string(decoded), ":")
		if !ok || username == "" {
			return Credential{}, errors.New("auth field does not decode to username:password")
		}
		return Credential{Username: username, Password: password}, nil
	}
	if e.Username == "" && e.Password == "" {
		return Credential{}, nil
	}
	if e.Username == "" || e.Password == "" {
		return Credential{}, errors.New("username and password must both be set")
	}
	return Credential{Username: e.Username, Password: e.Password}, nil
}
