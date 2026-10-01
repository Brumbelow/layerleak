package registry

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

func TestNewClientReportsConfigurationErrorsEagerly(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		wantErr string
	}{
		{name: "invalid base url scheme", options: Options{BaseURL: "htps://registry.example"}, wantErr: "https"},
		{name: "base url with query", options: Options{BaseURL: "https://registry.example/?x=1"}, wantErr: "query"},
		{name: "base url with userinfo", options: Options{BaseURL: "https://user:pass@registry.example"}, wantErr: "userinfo"},
		{name: "invalid auth url", options: Options{AuthURL: "not a url"}, wantErr: "registry auth url"},
		{name: "http base url without allowlist", options: Options{BaseURL: "http://registry.internal:5000"}, wantErr: "https"},
		{name: "http base url not in allowlist", options: Options{BaseURL: "http://other.internal:5000", AllowedPrivateRegistryHosts: []string{"registry.internal:5000"}}, wantErr: "allowlisted"},
		{name: "http auth url not in allowlist", options: Options{AuthURL: "http://auth.internal/token", AllowedPrivateRegistryHosts: []string{"registry.internal:5000"}}, wantErr: "allowlisted"},
		{name: "invalid allowlist entry", options: Options{AllowedPrivateRegistryHosts: []string{"https://registry.internal"}}, wantErr: "invalid allowed private host"},
		{name: "unbracketed ipv6 allowlist entry", options: Options{AllowedPrivateAuthHosts: []string{"2001:db8::1"}}, wantErr: "invalid allowed private host"},
		{name: "custom round tripper without override", options: Options{HTTPClient: &http.Client{Transport: roundTripFunc(nil)}}, wantErr: "AllowPrivateHosts"},
		{name: "insecure tls", options: Options{HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}, wantErr: "verify TLS"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(test.options)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewClient() error = %v, want %q", err, test.wantErr)
			}
			if client != nil {
				t.Fatal("NewClient() returned a client alongside the error")
			}
		})
	}
}

func TestNewClientAcceptsValidConfigurations(t *testing.T) {
	for name, options := range map[string]Options{
		"defaults":              {},
		"explicit docker hub":   {BaseURL: "https://registry-1.docker.io", AuthURL: "https://auth.docker.io/token"},
		"allowlisted http":      {BaseURL: "http://registry.internal:5000", AllowedPrivateRegistryHosts: []string{"registry.internal:5000"}},
		"test transport":        {HTTPClient: &http.Client{Transport: roundTripFunc(nil)}, AllowPrivateHosts: true},
		"ipv6 allowlist entry":  {AllowedPrivateRegistryHosts: []string{"[2001:db8::1]:5000"}},
		"custom http transport": {HTTPClient: &http.Client{Transport: &http.Transport{}}},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(options)
			if err != nil || client == nil {
				t.Fatalf("NewClient() = %v, %v", client, err)
			}
		})
	}
}

func TestMustNewClientPanicsOnConfigurationError(t *testing.T) {
	defer func() {
		recovered := recover()
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "registry") {
			t.Fatalf("recover() = %v", recovered)
		}
	}()
	MustNewClient(Options{BaseURL: "htps://registry.example"})
	t.Fatal("MustNewClient() did not panic")
}
