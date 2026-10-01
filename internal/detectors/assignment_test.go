package detectors

import (
	"strings"
	"testing"
)

// assignmentSecret is a synthetic high-entropy value with no vendor prefix, so
// only the generic assignment detectors can find it.
const assignmentSecret = "q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5"

func requireSingleValueMatch(t *testing.T, matches []Match, detector, value string) Match {
	t.Helper()
	var found []Match
	for _, match := range matches {
		if match.Value == value {
			found = append(found, match)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one match for the value, got %d in %#v", len(found), matches)
	}
	if found[0].Detector != detector {
		t.Fatalf("match.Detector = %q, want %q (%#v)", found[0].Detector, detector, matches)
	}
	return found[0]
}

// DET-01: unquoted KEY=VALUE is the dominant secret shape in images.
func TestKeywordEntropyDetectsUnquotedAssignments(t *testing.T) {
	set := Default()
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: ".env unquoted", input: ScanInput{Path: "/app/.env", Content: "DB_PASSWORD=" + assignmentSecret + "\n"}},
		{name: "shell export unquoted", input: ScanInput{Path: "/app/entrypoint.sh", Content: "export API_TOKEN=" + assignmentSecret}},
		{name: "java properties", input: ScanInput{Path: "/app/application.properties", Content: "db.password=" + assignmentSecret}},
		// The file-format rule outranks the generic one on the same span.
		{name: "my.cnf", input: ScanInput{Path: "/root/.my.cnf", Content: "[client]\npassword=" + assignmentSecret + "\n"}, detector: "mysql_client_password"},
		{name: "generic cnf", input: ScanInput{Path: "/etc/app/service.cnf", Content: "[client]\npassword=" + assignmentSecret + "\n"}},
		{name: "bare password=", input: ScanInput{Content: "password=" + assignmentSecret}},
		{name: "history RUN export", input: ScanInput{Key: "history[3].created_by", Content: "RUN export DB_PASSWORD=" + assignmentSecret + " && ./migrate"}},
		{name: "history ENV", input: ScanInput{Key: "history[1].created_by", Content: "/bin/sh -c #(nop)  ENV DB_PASSWORD=" + assignmentSecret}},
		{name: "dockerfile ENV space form", input: ScanInput{Path: "/app/Dockerfile", Content: "ENV DB_PASSWORD " + assignmentSecret + "\n"}},
		{name: "base64 padded value keeps its padding", input: ScanInput{Content: "AUTH_SECRET=" + assignmentSecret + "=="}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := assignmentSecret
			if strings.HasSuffix(tt.input.Content, "==") {
				want += "=="
			}
			detector := tt.detector
			if detector == "" {
				detector = "keyword_entropy"
			}
			requireSingleValueMatch(t, set.Scan(tt.input), detector, want)
		})
	}
}

// DET-02: whitespace between the operator and the opening quote must not
// defeat the assignment check.
func TestHasAssignedValuePrefixAcceptsCommonSyntaxes(t *testing.T) {
	for _, prefix := range []string{
		`"password": "`, `password: "`, `password: '`, `password = "`, `password => '`, `'password' => '`,
		`Password: "`, `"password":"`, `password="`, `password: `, `password=`, `password := "`, `password:="`,
		"password = `",
	} {
		if !hasAssignedValuePrefix(prefix) {
			t.Fatalf("hasAssignedValuePrefix(%q) = false", prefix)
		}
	}
	for _, prefix := range []string{`password "`, `password `, `Authorization: Basic `, ``, `"password"`} {
		if hasAssignedValuePrefix(prefix) {
			t.Fatalf("hasAssignedValuePrefix(%q) = true", prefix)
		}
	}
}

func TestKeywordEntropyDetectsFourteenAssignmentSyntaxes(t *testing.T) {
	set := Default()
	tests := []struct {
		name    string
		content string
	}{
		{name: "json pretty", content: "{\n  \"password\": \"" + assignmentSecret + "\"\n}"},
		{name: "json compact", content: `{"password":"` + assignmentSecret + `"}`},
		{name: "yaml plain", content: "password: " + assignmentSecret},
		{name: "yaml double quoted", content: "password: \"" + assignmentSecret + "\""},
		{name: "yaml single quoted", content: "password: '" + assignmentSecret + "'"},
		{name: "toml and hcl", content: "password = \"" + assignmentSecret + "\""},
		{name: "python", content: "PASSWORD = '" + assignmentSecret + "'"},
		{name: "javascript object literal", content: "  password: \"" + assignmentSecret + "\","},
		{name: "go struct literal", content: "\tPassword: \"" + assignmentSecret + "\","},
		{name: "ruby hash rocket", content: ":password => '" + assignmentSecret + "'"},
		{name: "php array", content: "'password' => '" + assignmentSecret + "',"},
		{name: "ini", content: "password=" + assignmentSecret},
		{name: "ini spaced", content: "password = " + assignmentSecret},
		{name: "xml attribute", content: `<datasource password="` + assignmentSecret + `" />`},
		{name: "shell export quoted", content: "export PASSWORD=\"" + assignmentSecret + "\""},
		{name: "go short declaration", content: "password := \"" + assignmentSecret + "\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireSingleValueMatch(t, set.Scan(ScanInput{Path: "/app/config", Content: tt.content}), "keyword_entropy", assignmentSecret)
		})
	}
}

// DET-03: metadata sources carry "KEY=VALUE" as content; the finding must
// cover the value alone so it shares spans and fingerprints with the same
// secret found in a file and never duplicates a specific rule's finding.
func TestMetadataFindingsReportValueOnlySpans(t *testing.T) {
	set := Default()
	githubToken := "ghp_" + strings.Repeat("1234567890", 3) + "abcdef"
	tests := []struct {
		name     string
		input    ScanInput
		detector string
		value    string
	}{
		{name: "env generic password", input: ScanInput{Key: "DB_PASSWORD", Content: "DB_PASSWORD=" + assignmentSecret}, detector: "keyword_entropy", value: assignmentSecret},
		{name: "env client secret", input: ScanInput{Key: "CLIENT_SECRET", Content: "CLIENT_SECRET=" + assignmentSecret}, detector: "assigned_sensitive_value", value: assignmentSecret},
		{name: "env github token", input: ScanInput{Key: "GH_TOKEN", Content: "GH_TOKEN=" + githubToken}, detector: "github_token", value: githubToken},
		{name: "label dotted key", input: ScanInput{Key: "com.example.token", Content: "com.example.token=" + assignmentSecret}, detector: "keyword_entropy", value: assignmentSecret},
		{name: "label dotted key github token", input: ScanInput{Key: "org.opencontainers.image.token", Content: "org.opencontainers.image.token=" + githubToken}, detector: "github_token", value: githubToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			if len(matches) != 1 {
				t.Fatalf("len(matches) = %d, want 1: %#v", len(matches), matches)
			}
			match := matches[0]
			if match.Detector != tt.detector || match.Value != tt.value {
				t.Fatalf("match = %#v, want %s %q", match, tt.detector, tt.value)
			}
			wantStart := len(tt.input.Content) - len(tt.value)
			if match.Start != wantStart || match.End != len(tt.input.Content) {
				t.Fatalf("span = [%d:%d], want [%d:%d]", match.Start, match.End, wantStart, len(tt.input.Content))
			}
		})
	}
}

func TestEnvAndFileFindingsShareTheMatchedValue(t *testing.T) {
	set := Default()
	envMatches := set.Scan(ScanInput{Key: "DB_PASSWORD", Content: "DB_PASSWORD=" + assignmentSecret})
	fileMatches := set.Scan(ScanInput{Path: "/app/.env", Content: "DB_PASSWORD=" + assignmentSecret + "\n"})
	if len(envMatches) != 1 || len(fileMatches) != 1 {
		t.Fatalf("env matches = %#v, file matches = %#v", envMatches, fileMatches)
	}
	if envMatches[0].Value != fileMatches[0].Value || envMatches[0].Start != fileMatches[0].Start {
		t.Fatalf("env match %#v differs from file match %#v", envMatches[0], fileMatches[0])
	}
}

// DET-38: a self-identifying rule must label an identical span, and the
// generic rule's declared confidence must be the one it reports.
func TestSpecificRuleWinsIdenticalSpanOverAssignedSensitiveValue(t *testing.T) {
	set := Default()
	githubToken := "ghp_" + strings.Repeat("1234567890", 3) + "abcdef"
	matches := set.Scan(ScanInput{Key: "ACCESS_TOKEN", Content: "ACCESS_TOKEN=" + githubToken})
	if len(matches) != 1 {
		t.Fatalf("len(matches) = %d: %#v", len(matches), matches)
	}
	if matches[0].Detector != "github_token" {
		t.Fatalf("match.Detector = %q, want github_token", matches[0].Detector)
	}

	generic := set.Scan(ScanInput{Key: "CLIENT_SECRET", Content: "CLIENT_SECRET=" + assignmentSecret})
	match := requireSingleValueMatch(t, generic, "assigned_sensitive_value", assignmentSecret)
	if match.Confidence != ConfidenceHigh {
		t.Fatalf("match.Confidence = %q", match.Confidence)
	}
	if match.Priority >= priorityLocal {
		t.Fatalf("match.Priority = %d, want below priorityLocal (%d)", match.Priority, priorityLocal)
	}
	for _, detector := range set.detectors {
		if kv, ok := detector.(keyValueDetector); ok && kv.name == "assigned_sensitive_value" && kv.base != ConfidenceHigh {
			t.Fatalf("assigned_sensitive_value declares %q but always reports high", kv.base)
		}
	}
}
