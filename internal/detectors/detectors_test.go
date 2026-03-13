package detectors

import "testing"

func TestDefaultSetScan(t *testing.T) {
	tests := []struct {
		name         string
		input        ScanInput
		wantDetector string
	}{
		{
			name: "github token",
			input: ScanInput{
				Content: "token=ghp_123456789012345678901234567890123456",
			},
			wantDetector: "github_token",
		},
		{
			name: "docker auth blob",
			input: ScanInput{
				Content: `{"auth":"dXNlcjpwYXNz"}`,
				Path:    "/root/.docker/config.json",
			},
			wantDetector: "docker_auth_blob",
		},
		{
			name: "jwt",
			input: ScanInput{
				Content: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturetoken",
			},
			wantDetector: "jwt",
		},
	}

	set := Default()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			if len(matches) == 0 {
				t.Fatal("len(matches) = 0")
			}
			found := false
			for _, match := range matches {
				if match.Detector == tt.wantDetector {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected detector %q in %#v", tt.wantDetector, matches)
			}
		})
	}
}

func TestKeywordEntropyUsesPathWeighting(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{
		Path:    "/app/.env",
		Key:     "SECRET_VALUE",
		Content: "SECRET_VALUE=q7Y8zX6wV4uT2sR0pN9mL7kJ5hG3fD1cB5",
	})

	found := false
	for _, match := range matches {
		if match.Detector == "keyword_entropy" {
			found = true
			if match.Confidence == ConfidenceLow {
				t.Fatalf("match.Confidence = %q", match.Confidence)
			}
		}
	}

	if !found {
		t.Fatal("expected keyword_entropy match")
	}
}
