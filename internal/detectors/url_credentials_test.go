package detectors

import (
	"strings"
	"testing"
)

// ageBech32UpperBody is a synthetic 58-symbol Bech32 body (the charset
// repeated), the shape age-keygen and SOPS key files actually carry.
const ageBech32UpperBody = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" + "QPZRY9X8GF2TVDW0S3JN54KHCE"

// DET-06: real age identities are uppercase Bech32.
func TestAgeSecretKeyMatchesRealBech32Shapes(t *testing.T) {
	set := Default()
	prefix := "AGE-" + "SECRET-KEY-1"

	t.Run("uppercase identity from a sops key file", func(t *testing.T) {
		content := "# created: 2026-01-01T00:00:00Z\n# public key: age1" + strings.ToLower(ageBech32UpperBody) + "\n" + prefix + ageBech32UpperBody + "\n"
		matches := set.Scan(ScanInput{Path: "/root/.config/sops/age/keys.txt", Content: content})
		match, ok := findDetectorMatch(matches, "age_secret_key")
		if !ok {
			t.Fatalf("expected age_secret_key in %#v", matches)
		}
		if match.Value != prefix+ageBech32UpperBody {
			t.Fatalf("match.Value = %q", match.Value)
		}
		if match.Confidence != ConfidenceHigh {
			t.Fatalf("match.Confidence = %q", match.Confidence)
		}
	})

	t.Run("mixed case is not bech32", func(t *testing.T) {
		body := ageBech32UpperBody[:29] + strings.ToLower(ageBech32UpperBody[29:])
		for _, match := range set.Scan(ScanInput{Content: prefix + body}) {
			if match.Detector == "age_secret_key" {
				t.Fatalf("unexpected age_secret_key match: %#v", match)
			}
		}
	})

	t.Run("symbols outside the bech32 charset are rejected", func(t *testing.T) {
		body := "B" + ageBech32UpperBody[1:] // 'B' is not a Bech32 symbol
		for _, match := range set.Scan(ScanInput{Content: prefix + body}) {
			if match.Detector == "age_secret_key" {
				t.Fatalf("unexpected age_secret_key match: %#v", match)
			}
		}
	})
}

// DET-07: the host class must stop at quotes and delimiters so compact JSON
// is found and the value (hence the fingerprint) is the URL alone; the scheme
// is case-insensitive.
func TestBasicAuthURLStopsAtQuotesAndDelimiters(t *testing.T) {
	set := Default()
	url := "https://deploy:Sup3rS3cretPwXyz@registry.internal"
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "bare", content: url, want: url},
		{name: "with path", content: url + "/v2/", want: url},
		{name: "compact json", content: `{"registry":"` + url + `"}`, want: url},
		{name: "json followed by comma", content: `{"a":"` + url + `","b":1}`, want: url},
		{name: "python single quote and paren", content: "client('" + url + "')", want: url},
		{name: "js single quote and semicolon", content: "const u = '" + url + "';", want: url},
		{name: "quoted yaml", content: "registry: \"" + url + "/\"", want: url},
		{name: "angle brackets", content: "<" + url + ">", want: url},
		{name: "uppercase scheme", content: "HTTPS://deploy:Sup3rS3cretPwXyz@registry.internal", want: "HTTPS://deploy:Sup3rS3cretPwXyz@registry.internal"},
		{name: "port and ipv6 host", content: "https://deploy:Sup3rS3cretPwXyz@[2001:db8::1]:8443/x", want: "https://deploy:Sup3rS3cretPwXyz@[2001:db8::1]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, ok := findDetectorMatch(set.Scan(ScanInput{Content: tt.content}), "basic_auth_url")
			if !ok {
				t.Fatalf("expected basic_auth_url in %#v", set.Scan(ScanInput{Content: tt.content}))
			}
			if match.Value != tt.want {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.want)
			}
		})
	}
}

func TestBasicAuthURLAllowsEmptyUsername(t *testing.T) {
	match, ok := findDetectorMatch(Default().Scan(ScanInput{Content: "https://:Sup3rS3cretPwXyz@registry.internal/v2/"}), "basic_auth_url")
	if !ok {
		t.Fatal("expected basic_auth_url for an empty username")
	}
	if match.Value != "https://:Sup3rS3cretPwXyz@registry.internal" {
		t.Fatalf("match.Value = %q", match.Value)
	}
}

// DET-28: connection URLs with embedded passwords are the most common secret
// in container ENV and .env files.
func TestConnectionURLCredentialsDetector(t *testing.T) {
	set := Default()
	tests := []struct {
		name  string
		input ScanInput
		want  string
	}{
		{
			name:  "postgres in a .env file",
			input: ScanInput{Path: "/app/.env", Content: "DATABASE_URL=postgres://app:Sup3rS3cretPw9@db.internal:5432/app?sslmode=require\n"},
			want:  "postgres://app:Sup3rS3cretPw9@db.internal:5432",
		},
		{
			name:  "postgresql env source",
			input: ScanInput{Key: "DATABASE_URL", Content: "DATABASE_URL=postgresql://app:Sup3rS3cretPw9@db.internal/app"},
			want:  "postgresql://app:Sup3rS3cretPw9@db.internal",
		},
		{
			name:  "mysql",
			input: ScanInput{Content: "mysql://root:Sup3rS3cretPw9@mysql.internal:3306/shop"},
			want:  "mysql://root:Sup3rS3cretPw9@mysql.internal:3306",
		},
		{
			name:  "mongodb srv with replica hosts",
			input: ScanInput{Key: "MONGO_URI", Content: "MONGO_URI=mongodb+srv://app:Sup3rS3cretPw9@cluster0.abcde.mongodb.net/app?retryWrites=true"},
			want:  "mongodb+srv://app:Sup3rS3cretPw9@cluster0.abcde.mongodb.net",
		},
		{
			name:  "mongodb host list",
			input: ScanInput{Content: "mongodb://app:Sup3rS3cretPw9@host1.internal:27017,host2.internal:27017/app"},
			want:  "mongodb://app:Sup3rS3cretPw9@host1.internal:27017,host2.internal:27017",
		},
		{
			name:  "redis with empty username",
			input: ScanInput{Key: "REDIS_URL", Content: "REDIS_URL=redis://:Sup3rS3cretPw9@cache.internal:6379/0"},
			want:  "redis://:Sup3rS3cretPw9@cache.internal:6379",
		},
		{
			name:  "rediss",
			input: ScanInput{Content: "rediss://default:Sup3rS3cretPw9@cache.internal:6380"},
			want:  "rediss://default:Sup3rS3cretPw9@cache.internal:6380",
		},
		{
			name:  "amqp in yaml",
			input: ScanInput{Path: "/app/config.yaml", Content: "broker:\n  url: \"amqp://worker:Sup3rS3cretPw9@rabbit.internal:5672/vhost\"\n"},
			want:  "amqp://worker:Sup3rS3cretPw9@rabbit.internal:5672",
		},
		{
			name:  "amqps compact json",
			input: ScanInput{Content: `{"broker":"amqps://worker:Sup3rS3cretPw9@rabbit.internal"}`},
			want:  "amqps://worker:Sup3rS3cretPw9@rabbit.internal",
		},
		{
			name:  "cloudinary",
			input: ScanInput{Key: "CLOUDINARY_URL", Content: "CLOUDINARY_URL=cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz0@demo-cloud"},
			want:  "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz0@demo-cloud",
		},
		{
			name:  "uppercase scheme in docker history",
			input: ScanInput{Key: "history[0].created_by", Content: "RUN export DATABASE_URL=POSTGRES://app:Sup3rS3cretPw9@db.internal/app && migrate"},
			want:  "POSTGRES://app:Sup3rS3cretPw9@db.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			match, ok := findDetectorMatch(matches, "connection_url_credentials")
			if !ok {
				t.Fatalf("expected connection_url_credentials in %#v", matches)
			}
			if match.Value != tt.want {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.want)
			}
			if match.Confidence != ConfidenceHigh {
				t.Fatalf("match.Confidence = %q", match.Confidence)
			}
		})
	}
}

func TestConnectionURLCredentialsRequiresAPassword(t *testing.T) {
	set := Default()
	for _, content := range []string{
		"DATABASE_URL=postgres://db.internal:5432/app",
		"DATABASE_URL=postgres://app@db.internal:5432/app",
		"REDIS_URL=redis://cache.internal:6379/0",
		"MONGO_URI=mongodb://localhost:27017",
		"postgres://app:@db.internal/app",
		"https://registry.internal/v2/",
	} {
		for _, match := range set.Scan(ScanInput{Content: content}) {
			if match.Detector == "connection_url_credentials" || match.Detector == "basic_auth_url" {
				t.Fatalf("unexpected %s match for %q: %#v", match.Detector, content, match)
			}
		}
	}
}

func TestConnectionURLCredentialsDiscardsPlaceholderPairsOnReservedHosts(t *testing.T) {
	for _, match := range Default().Scan(ScanInput{Content: "postgres://admin:admin@localhost/app"}) {
		if match.Detector == "connection_url_credentials" {
			t.Fatalf("unexpected connection_url_credentials match: %#v", match)
		}
	}
}
