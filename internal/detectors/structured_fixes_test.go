package detectors

import "testing"

// DET-18: git credential-store percent-encodes reserved characters in the
// password; the finding must cover the raw encoded bytes so the span check in
// the normaliser holds and the structured match is not dropped.
func TestGitCredentialsDetectorKeepsPercentEncodedPasswords(t *testing.T) {
	set := Default()
	for _, encoded := range []string{"p%40ssw0rdXyzAbc", "p%2Fssw0rd%23XyzAbc", "plainPassw0rdXyz"} {
		content := "https://deploy:" + encoded + "@github.com/org/repo.git\n"
		matches := set.Scan(ScanInput{Path: "/root/.git-credentials", Content: content})
		match, ok := findDetectorMatch(matches, "git_credentials_password")
		if !ok {
			t.Fatalf("%s: expected git_credentials_password in %#v", encoded, matches)
		}
		if match.Value != encoded {
			t.Fatalf("%s: match.Value = %q", encoded, match.Value)
		}
		if content[match.Start:match.End] != match.Value {
			t.Fatalf("%s: span [%d:%d] does not cover the value", encoded, match.Start, match.End)
		}
	}
}

// DET-19: CRLF line endings must not disable the surrounding-quote check in
// the INI parser.
func TestAWSSharedCredentialsAcceptQuotedCRLFValues(t *testing.T) {
	// Assembled at run time so no 40-character secret-shaped literal sits in
	// the source tree.
	secretValue := "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYDkPqLmNsTu"
	content := "[default]\r\naws_access_key_id = \"AKIA1234567890ABCDEF\"\r\naws_secret_access_key = \"" + secretValue + "\"\r\n"
	matches := Default().Scan(ScanInput{Path: "/root/.aws/credentials", Content: content})
	access, ok := findDetectorMatch(matches, "aws_shared_credentials_access_key_id")
	if !ok || access.Value != "AKIA1234567890ABCDEF" {
		t.Fatalf("access key match = %#v (all: %#v)", access, matches)
	}
	secret, ok := findDetectorMatch(matches, "aws_shared_credentials_secret_access_key")
	if !ok || secret.Value != secretValue {
		t.Fatalf("secret match = %#v", secret)
	}
	for _, match := range matches {
		if match.Detector == "aws_access_key_id" || match.Detector == "aws_secret_access_key" {
			t.Fatalf("generic rule survived next to the structured match: %#v", match)
		}
	}
}

func TestParseINIKeyValueStripsQuotesOnCRLFLines(t *testing.T) {
	key, value, start, end, ok := parseINIKeyValue("aws_secret_access_key = \"abc\"\r")
	if !ok || key != "aws_secret_access_key" || value != "abc" {
		t.Fatalf("parseINIKeyValue() = (%q, %q, %d, %d, %t)", key, value, start, end, ok)
	}
}

// DET-39: a UTF-8 BOM before the first section header must not merge that
// profile into the implicit default section.
func TestAWSSharedCredentialsHonourBOMSectionHeader(t *testing.T) {
	content := "\uFEFF[prod]\naws_access_key_id = AKIAPRODPRODPRODPROD\n[default]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = " + testAWSSecret + "\n"
	matches := Default().Scan(ScanInput{Path: "/root/.aws/credentials", Content: content})

	var prod, def Match
	for _, match := range matches {
		if match.Detector != "aws_shared_credentials_access_key_id" {
			continue
		}
		switch match.Value {
		case "AKIAPRODPRODPRODPROD":
			prod = match
		case "AKIA1234567890ABCDEF":
			def = match
		}
	}
	if prod.Value == "" || def.Value == "" {
		t.Fatalf("expected both access keys in %#v", matches)
	}
	if prod.Confidence != ConfidenceMedium {
		t.Fatalf("unpaired [prod] key was promoted by [default]'s secret: %#v", prod)
	}
	if def.Confidence != ConfidenceHigh {
		t.Fatalf("paired [default] key confidence = %q", def.Confidence)
	}

	bomKey := Default().Scan(ScanInput{Path: "/root/.aws/credentials", Content: "\uFEFFaws_access_key_id = AKIA1234567890ABCDEF\n"})
	match, ok := findDetectorMatch(bomKey, "aws_shared_credentials_access_key_id")
	if !ok || match.Value != "AKIA1234567890ABCDEF" || match.Start != len("\uFEFFaws_access_key_id = ") {
		t.Fatalf("BOM before the key line: %#v", bomKey)
	}
}
