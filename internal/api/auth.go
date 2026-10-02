package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

const (
	// challengeRealmOnly is the WWW-Authenticate value on every 401. RFC 6750
	// adds error="invalid_token" when credentials were presented but refused.
	challengeRealmOnly    = `Bearer realm="layerleak"`
	challengeInvalidToken = challengeRealmOnly + `, error="invalid_token"`
	// protectedPathPrefix is the subtree that requires a token when
	// authentication is enabled. The health probes outside it stay open.
	protectedPathPrefix = "/api/"
	// tokenIDLength is how many hex characters of a token's SHA-256 digest
	// are logged to tell configured tokens apart. The prefix identifies a
	// token without revealing it.
	tokenIDLength = 8
	// maxAuthorizationHeaderBytes bounds the header the matcher hashes.
	maxAuthorizationHeaderBytes = 4096
)

// authFailure classifies why a request was refused; the value is logged, the
// header mapping is fixed and no token material is ever included.
type authFailure string

const (
	authMissing   authFailure = "missing_token"
	authMalformed authFailure = "malformed_authorization"
	authUnknown   authFailure = "unknown_token"
)

// bearerAuth matches presented tokens against the configured SHA-256 digests.
// Every digest is compared with crypto/subtle on every request, so the time
// taken does not depend on which token (if any) matched.
type bearerAuth struct {
	digests [][]byte
}

// newBearerAuth validates the configured digests. Nil or empty disables
// authentication; a digest that is not SHA-256 sized is a programming error
// surfaced at construction rather than as a permanently failing matcher.
func newBearerAuth(digests [][]byte) (*bearerAuth, error) {
	auth := &bearerAuth{digests: make([][]byte, 0, len(digests))}
	for index, digest := range digests {
		if len(digest) != sha256.Size {
			return nil, fmt.Errorf("bearer token digest %d has %d bytes, want %d", index+1, len(digest), sha256.Size)
		}
		auth.digests = append(auth.digests, append([]byte(nil), digest...))
	}
	return auth, nil
}

func (a *bearerAuth) enabled() bool {
	return a != nil && len(a.digests) > 0
}

// requiresToken reports whether the request path is inside the protected
// subtree. Unclean paths were already answered 404 by the middleware.
func requiresToken(requestPath string) bool {
	return strings.HasPrefix(requestPath, protectedPathPrefix)
}

// authenticate checks the Authorization header. On success it returns the
// token id (a short digest prefix) for the debug log. On failure it returns
// the classification and the WWW-Authenticate value to send.
func (a *bearerAuth) authenticate(header string) (tokenID string, failure authFailure, challenge string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", authMissing, challengeRealmOnly
	}
	if len(header) > maxAuthorizationHeaderBytes {
		return "", authMalformed, challengeInvalidToken
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", authMalformed, challengeInvalidToken
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", authMalformed, challengeInvalidToken
	}
	presented := sha256.Sum256([]byte(token))
	matched := 0
	for _, digest := range a.digests {
		matched |= subtle.ConstantTimeCompare(presented[:], digest)
	}
	if matched != 1 {
		return "", authUnknown, challengeInvalidToken
	}
	return hex.EncodeToString(presented[:])[:tokenIDLength], "", ""
}

// authorize enforces the token on protected paths. It returns true when the
// request may proceed and has already written the 401 otherwise.
func (h *Handler) authorize(writer http.ResponseWriter, request *http.Request, requestID string) bool {
	if !h.auth.enabled() || !requiresToken(request.URL.Path) {
		return true
	}
	tokenID, failure, challenge := h.auth.authenticate(request.Header.Get("Authorization"))
	if failure != "" {
		h.logger.Info("api request unauthorized", "reason", string(failure), "request_id", requestID)
		writer.Header().Set("WWW-Authenticate", challenge)
		writeAPIError(writer, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
		return false
	}
	h.logger.Debug("api request authenticated", "token_id", tokenID, "request_id", requestID)
	return true
}
