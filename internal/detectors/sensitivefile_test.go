package detectors

import (
	"slices"
	"testing"
)

// LAY-12: sensitive artifacts are classified by path when their content
// cannot be scanned.
func TestSensitiveFileClassification(t *testing.T) {
	tests := []struct {
		path       string
		detector   string
		confidence Confidence
	}{
		{path: "root/.ssh/id_rsa", detector: "sensitive_file_private_key", confidence: ConfidenceMedium},
		{path: "/home/app/.ssh/id_ed25519", detector: "sensitive_file_private_key", confidence: ConfidenceMedium},
		{path: "home/app/.ssh/id_ed25519_sk", detector: "sensitive_file_private_key", confidence: ConfidenceMedium},
		{path: "home/app/.ssh/id_rsa_deploy", detector: "sensitive_file_private_key", confidence: ConfidenceMedium},
		{path: "etc/ssl/private/server.p12", detector: "sensitive_file_keystore", confidence: ConfidenceMedium},
		{path: "app/certs/client.PFX", detector: "sensitive_file_keystore", confidence: ConfidenceMedium},
		{path: "opt/app/keystore.jks", detector: "sensitive_file_keystore", confidence: ConfidenceLow},
		{path: "opt/app/server.keystore", detector: "sensitive_file_keystore", confidence: ConfidenceLow},
		{path: "root/Passwords.kdbx", detector: "sensitive_file_password_database", confidence: ConfidenceMedium},
		{path: "root/.netrc", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/_netrc", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/.pgpass", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/.git-credentials", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/.aws/credentials", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: ".aws/credentials", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/.docker/config.json", detector: "sensitive_file_credential_store", confidence: ConfidenceMedium},
		{path: "root/.gnupg/secring.gpg", detector: "sensitive_file_gpg_keyring", confidence: ConfidenceMedium},
		{path: "root/.gnupg/private-keys-v1.d/0123456789ABCDEF0123456789ABCDEF01234567.key", detector: "sensitive_file_gpg_keyring", confidence: ConfidenceMedium},
		{path: `C:\Users\app\.ssh\id_rsa`, detector: "sensitive_file_private_key", confidence: ConfidenceMedium},
		// Not sensitive by path.
		{path: "root/.ssh/id_rsa.pub"},
		{path: "root/.ssh/id_rsa-cert.pub"},
		{path: "root/.ssh/known_hosts"},
		{path: "usr/lib/jvm/lib/security/cacerts"},
		{path: "opt/app/truststore.jks"},
		{path: "opt/app/client-truststore.p12"},
		{path: "app/config.json"},
		{path: "usr/bin/tool"},
		{path: "root/.gnupg/pubring.gpg"},
		{path: "root/.gnupg/private-keys-v1.d/README"},
		{path: ""},
	}
	set := Default()
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			matches := set.ScanPath(tt.path)
			if tt.detector == "" {
				if len(matches) != 0 {
					t.Fatalf("ScanPath(%q) = %#v, want none", tt.path, matches)
				}
				return
			}
			if len(matches) != 1 {
				t.Fatalf("ScanPath(%q) = %#v, want one match", tt.path, matches)
			}
			match := matches[0]
			if match.Detector != tt.detector || match.Confidence != tt.confidence {
				t.Fatalf("match = %#v, want %s/%s", match, tt.detector, tt.confidence)
			}
			if match.Value != tt.path || match.Start != 0 || match.End != len(tt.path) {
				t.Fatalf("match does not cover the path: %#v", match)
			}
			if match.Priority != priorityStructured {
				t.Fatalf("match.Priority = %d", match.Priority)
			}
		})
	}
}

// The family never matches content: a readable id_rsa is reported by the PEM
// rule alone, and its ids are all in the catalog.
func TestSensitiveFileDetectorIsPathOnly(t *testing.T) {
	set := Default()
	matches := set.Scan(ScanInput{Path: "/root/.ssh/id_rsa", Content: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"})
	for _, match := range matches {
		if match.Detector != "pem_private_key" {
			t.Fatalf("unexpected content match: %#v", match)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %#v", matches)
	}
	catalog := set.Catalog()
	for _, id := range (sensitiveFileDetector{}).IDs() {
		if !slices.Contains(catalog, id) {
			t.Fatalf("catalog is missing %q", id)
		}
	}
	if slices.Contains(catalog, "sensitive_file") {
		t.Fatal("strategy name sensitive_file is in the catalog but never appears in a finding")
	}
}
