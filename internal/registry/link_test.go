package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestNextLinkURLParsesRFC8288Shapes(t *testing.T) {
	const current = "https://registry.test/v2/library/app/tags/list?n=2"
	tests := []struct {
		name    string
		headers []string
		want    string
		wantOK  bool
		wantErr bool
	}{
		{name: "no header"},
		{
			name:    "canonical distribution shape",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "multiple relations in one header",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; rel="next", </v2/library/app/tags/list?n=2>; rel="prev"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "prev listed before next",
			headers: []string{`</v2/library/app/tags/list?n=2>; rel="prev", </v2/library/app/tags/list?n=2&last=2.0>; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "unquoted rel",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; rel=next`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "parameters in another order",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; type="application/json"; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "whitespace and uppercase relation",
			headers: []string{`  < /v2/library/app/tags/list?n=2&last=2.0 >  ;  REL = "NEXT"  `},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "relation list containing next",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; rel="alternate next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "quoted comma inside another parameter",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; title="a, b"; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "absolute same-host url",
			headers: []string{`<https://registry.test/v2/library/app/tags/list?n=2&last=2.0>; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "next in second header",
			headers: []string{`</v2/library/app/tags/list?n=2>; rel="prev"`, `</v2/library/app/tags/list?n=2&last=2.0>; rel="next"`},
			want:    "https://registry.test/v2/library/app/tags/list?n=2&last=2.0",
			wantOK:  true,
		},
		{
			name:    "prev only is the last page",
			headers: []string{`</v2/library/app/tags/list?n=2>; rel="prev"`},
		},
		{
			name:    "missing angle brackets",
			headers: []string{`/v2/library/app/tags/list?n=2&last=2.0; rel="next"`},
			wantErr: true,
		},
		{
			name:    "unterminated target",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0; rel="next"`},
			wantErr: true,
		},
		{
			name:    "unterminated quoted value",
			headers: []string{`</v2/library/app/tags/list?n=2&last=2.0>; rel="next`},
			wantErr: true,
		},
		{
			name:    "empty target",
			headers: []string{`<>; rel="next"`},
			wantErr: true,
		},
		{
			name:    "two next relations",
			headers: []string{`</v2/a?last=1>; rel="next", </v2/a?last=2>; rel="next"`},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok, err := nextLinkURL(current, test.headers)
			if test.wantErr {
				if err == nil {
					t.Fatalf("nextLinkURL() = %q, %t, nil; want error", got, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("nextLinkURL() error = %v", err)
			}
			if ok != test.wantOK || got != test.want {
				t.Fatalf("nextLinkURL() = %q, %t; want %q, %t", got, ok, test.want, test.wantOK)
			}
		})
	}
}

func TestNextLinkURLErrorsDoNotEchoHeader(t *testing.T) {
	const marker = "super-secret-marker"
	for _, header := range []string{
		marker + `; rel="next"`,
		`<` + marker,
		`<https://registry.test/` + marker + `>; rel="` + marker,
		`<https://registry.test/%ZZ` + marker + `>; rel="next"`,
	} {
		_, _, err := nextLinkURL("https://registry.test/v2/library/app/tags/list", []string{header})
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatalf("nextLinkURL(%q) error = %v", header, err)
		}
	}
}

func TestListTagsFollowsMultiRelationAndUnquotedLinks(t *testing.T) {
	for _, test := range []struct {
		name string
		link string
	}{
		{name: "multi relation", link: `</v2/library/app/tags/list?n=2&last=2.0>; rel="next", </v2/library/app/tags/list?n=2>; rel="prev"`},
		{name: "unquoted rel", link: `</v2/library/app/tags/list?n=2&last=2.0>; rel=next`},
		{name: "parameter order", link: `</v2/library/app/tags/list?n=2&last=2.0>; type="application/json"; rel="next"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host == "auth.test" {
					body, _ := json.Marshal(map[string]string{"token": "test-token"})
					return jsonResponse(http.StatusOK, "application/json", body, nil), nil
				}
				if request.Header.Get("Authorization") != "Bearer test-token" {
					return jsonResponse(http.StatusUnauthorized, "", nil, map[string]string{
						"Www-Authenticate": `Bearer realm="https://auth.test/token",service="registry.test",scope="repository:library/app:pull"`,
					}), nil
				}
				switch request.URL.Query().Get("last") {
				case "":
					return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["2.0","1.0"]}`), map[string]string{"Link": test.link}), nil
				case "2.0":
					return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["3.0"]}`), nil), nil
				default:
					return jsonResponse(http.StatusNotFound, "text/plain", []byte("not found"), nil), nil
				}
			})
			client := NewClient(Options{
				BaseURL:           "https://registry.test",
				AllowPrivateHosts: true,
				HTTPClient:        &http.Client{Transport: transport},
			})

			tags, err := client.ListTags(context.Background(), "library/app", 2, 0)
			if err != nil {
				t.Fatalf("ListTags() error = %v", err)
			}
			if strings.Join(tags, ",") != "1.0,2.0,3.0" {
				t.Fatalf("tags = %q", strings.Join(tags, ","))
			}
		})
	}
}

func TestListTagsFailsInsteadOfTruncatingOnMalformedLink(t *testing.T) {
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusOK, "application/json", []byte(`{"name":"library/app","tags":["2.0","1.0"]}`), map[string]string{
			"Link": `/v2/library/app/tags/list?n=2&last=2.0; rel="next"`,
		}), nil
	})
	client := NewClient(Options{
		BaseURL:           "https://registry.test",
		AllowPrivateHosts: true,
		HTTPClient:        &http.Client{Transport: transport},
	})

	tags, err := client.ListTags(context.Background(), "library/app", 2, 0)
	if err == nil {
		t.Fatalf("ListTags() error = nil, tags = %q", strings.Join(tags, ","))
	}
	if !strings.Contains(err.Error(), "pagination") {
		t.Fatalf("ListTags() error = %v", err)
	}
	if strings.Join(tags, ",") != "1.0,2.0" {
		t.Fatalf("partial tags = %q", strings.Join(tags, ","))
	}
	if requests != 1 {
		t.Fatalf("requests = %d", requests)
	}
}
