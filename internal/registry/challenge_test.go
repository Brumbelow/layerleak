package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// bearerChallengeShapes are the WWW-Authenticate shapes registries send; they
// drive TestParseBearerChallengeShapes and seed FuzzParseBearerChallenge.
var bearerChallengeShapes = []struct {
	name    string
	headers []string
	want    bearerChallenge
	wantErr string
}{
	{
		name:    "canonical docker hub challenge",
		headers: []string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`},
		want:    bearerChallenge{Realm: "https://auth.docker.io/token", Service: "registry.docker.io", Scope: "repository:library/alpine:pull"},
	},
	{
		name:    "comma inside quoted scope",
		headers: []string{`Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull,push"`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: "registry.test", Scope: "repository:library/app:pull,push"},
	},
	{
		name:    "comma inside quoted realm query",
		headers: []string{`Bearer realm="https://auth.test/token?x=1,2"`},
		want:    bearerChallenge{Realm: "https://auth.test/token?x=1,2"},
	},
	{
		name:    "escaped quote inside value",
		headers: []string{`Bearer realm="https://auth.test/token",service="reg\"istry"`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: `reg"istry`},
	},
	{
		name:    "whitespace and lowercase scheme",
		headers: []string{`bearer   realm = "https://auth.test/token" ,  service = "registry.test"`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: "registry.test"},
	},
	{
		name:    "unquoted token values",
		headers: []string{`Bearer realm=https://auth.test/token,service=registry.test`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: "registry.test"},
	},
	{
		name:    "basic listed before bearer in separate headers",
		headers: []string{`Basic realm="registry"`, `Bearer realm="https://auth.test/token",service="registry.test"`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: "registry.test"},
	},
	{
		name:    "basic and bearer in one header",
		headers: []string{`Basic realm="registry", Bearer realm="https://auth.test/token",service="registry.test"`},
		want:    bearerChallenge{Realm: "https://auth.test/token", Service: "registry.test"},
	},
	{
		name:    "unknown parameters are ignored",
		headers: []string{`Bearer realm="https://auth.test/token",error="insufficient_scope",error_description="The access token has insufficient scope, retry"`},
		want:    bearerChallenge{Realm: "https://auth.test/token"},
	},
	{
		name:    "first bearer challenge wins",
		headers: []string{`Bearer realm="https://auth.test/token", Bearer realm="https://other.test/token"`},
		want:    bearerChallenge{Realm: "https://auth.test/token"},
	},
	{
		name:    "missing header",
		wantErr: "registry auth challenge is missing",
	},
	{
		name:    "only basic",
		headers: []string{`Basic realm="super-secret-marker"`},
		wantErr: "unsupported registry auth challenge",
	},
	{
		name:    "bearer without realm",
		headers: []string{`Bearer service="registry.test"`},
		wantErr: "did not include a realm",
	},
	{
		name:    "unterminated quoted value",
		headers: []string{`Bearer realm="https://auth.test/token`},
		wantErr: "malformed",
	},
}

func TestParseBearerChallengeShapes(t *testing.T) {
	for _, test := range bearerChallengeShapes {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseBearerChallenges(test.headers)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseBearerChallenges() error = %v, want %q", err, test.wantErr)
				}
				if strings.Contains(err.Error(), "super-secret-marker") || strings.Contains(err.Error(), "auth.test") {
					t.Fatalf("error echoed header content: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBearerChallenges() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("parseBearerChallenges() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// FuzzParseBearerChallenge feeds hostile WWW-Authenticate values to the
// challenge parser. Newline-separated input is several header lines. The
// parser must not panic, must return only its fixed error messages (never
// header contents), and a parsed challenge has a realm and no field longer
// than the input it came from.
func FuzzParseBearerChallenge(f *testing.F) {
	for _, shape := range bearerChallengeShapes {
		f.Add(strings.Join(shape.headers, "\n"))
	}
	f.Add(`Bearer realm="a\`)
	f.Add(`Bearer realm=,service="x"`)
	f.Add(`=realm, Bearer`)
	f.Add(`Basic, Bearer realm="https://auth.test/token" scope="a" service=b`)
	fixedErrors := map[string]bool{
		"registry auth challenge is missing":            true,
		"unsupported registry auth challenge":           true,
		"bearer auth challenge did not include a realm": true,
		"malformed registry auth challenge":             true,
	}
	f.Fuzz(func(t *testing.T, input string) {
		headers := strings.Split(input, "\n")
		challenge, err := parseBearerChallenges(headers)
		_ = offersBasicChallenge(headers)
		if err != nil {
			if !fixedErrors[err.Error()] {
				t.Fatalf("parseBearerChallenges() error %q is not a fixed message", err)
			}
			return
		}
		if challenge.Realm == "" {
			t.Fatalf("parseBearerChallenges(%q) returned an empty realm without an error", input)
		}
		for name, field := range map[string]string{"realm": challenge.Realm, "service": challenge.Service, "scope": challenge.Scope} {
			if len(field) > len(input) {
				t.Fatalf("parseBearerChallenges(%q) %s has %d bytes, longer than the %d-byte input", input, name, len(field), len(input))
			}
		}
	})
}

func TestFetchManifestUsesBearerChallengeAfterBasic(t *testing.T) {
	scopes := make([]string, 0, 1)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "auth.test" {
			scopes = append(scopes, request.URL.Query().Get("scope"))
			body, _ := json.Marshal(map[string]string{"token": "test-token"})
			return jsonResponse(http.StatusOK, "application/json", body, nil), nil
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			response := jsonResponse(http.StatusUnauthorized, "", nil, nil)
			response.Header.Add("Www-Authenticate", `Basic realm="registry"`)
			response.Header.Add("Www-Authenticate", `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull,push"`)
			return response, nil
		}
		return jsonResponse(http.StatusOK, "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2}`), map[string]string{
			"Docker-Content-Digest": "sha256:" + strings.Repeat("a", 64),
		}), nil
	})
	client := MustNewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})

	if _, err := client.FetchManifest(context.Background(), "library/app", "latest"); err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	if strings.Join(scopes, ",") != "repository:library/app:pull,push" {
		t.Fatalf("token scopes = %q", scopes)
	}
}
