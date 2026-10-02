package detectors

import (
	"regexp"
	"slices"
	"testing"
)

// PRD-07 / PRD-26 / DET-26: detector identifiers are public API in 3.0.0.
// Catalog() must list every identifier a finding can carry, the structured
// readers' sub-identifiers included, and the names follow one convention.

// renamedDetectorIDs is the 3.0.0 rename table (old -> new). Documentation
// maps the old names at read time; there is no database migration.
var renamedDetectorIDs = map[string]string{
	"digitalocean_pat":            "digitalocean_personal_access_token",
	"stripe_key":                  "stripe_api_key",
	"gitlab_token":                "gitlab_personal_access_token",
	"jwt":                         "json_web_token",
	"hashicorp_vault_token":       "vault_token",
	"docker_config_identitytoken": "docker_config_identity_token",
	"npmrc_auth":                  "npmrc_basic_auth",
	"planetscale_token":           "planetscale_service_token",
}

func TestCatalogCoversEveryIdentifierEmittedOverTheCorpus(t *testing.T) {
	set := Default()
	catalog := set.Catalog()
	emitted := make(map[string]struct{})
	for _, document := range loadCorpusDocuments(t) {
		for _, match := range set.Scan(ScanInput{Content: document.Content, Path: document.Path, Key: document.Key}) {
			emitted[match.Detector] = struct{}{}
		}
	}
	// Inputs for the structured readers whose identifiers differ from Name().
	for _, input := range []ScanInput{
		// The secret is concatenated at run time so no 40-character secret-shaped
		// literal sits in the source tree.
		{Path: "/root/.aws/credentials", Content: "[default]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYDkPqLmNsTu" + "\naws_session_token = Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2nO4\n"},
		{Path: "/root/.git-credentials", Content: "https://deploy:Sup3rS3cretPwXyz@github.com/org/repo.git\n"},
	} {
		for _, match := range set.Scan(input) {
			emitted[match.Detector] = struct{}{}
		}
	}
	if len(emitted) < 25 {
		t.Fatalf("only %d identifiers emitted; the corpus is too thin to check the catalog", len(emitted))
	}
	for id := range emitted {
		if !slices.Contains(catalog, id) {
			t.Errorf("emitted identifier %q is missing from Catalog()", id)
		}
	}
	for _, id := range []string{"aws_shared_credentials_access_key_id", "aws_shared_credentials_secret_access_key", "aws_shared_credentials_session_token", "git_credentials_password"} {
		if _, ok := emitted[id]; !ok {
			t.Errorf("structured identifier %q was not emitted by its fixture", id)
		}
	}
	for _, name := range []string{"aws_shared_credentials", "git_credentials"} {
		if slices.Contains(catalog, name) {
			t.Errorf("strategy name %q is in the catalog but never appears in a finding", name)
		}
	}
}

func TestCatalogIsBuiltFromEmittedIdentifiers(t *testing.T) {
	set := Default()
	catalog := set.Catalog()
	identifier := regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)
	for _, detector := range set.detectors {
		ids := detector.IDs()
		if len(ids) == 0 {
			t.Fatalf("%s: IDs() is empty", detector.Name())
		}
		for _, id := range ids {
			if !identifier.MatchString(id) {
				t.Fatalf("identifier %q is not snake_case", id)
			}
			if !slices.Contains(catalog, id) {
				t.Fatalf("Catalog() is missing %q", id)
			}
		}
	}
	if !slices.IsSorted(catalog) || slices.Compact(slices.Clone(catalog)) == nil || len(slices.Compact(slices.Clone(catalog))) != len(catalog) {
		t.Fatalf("Catalog() is not sorted and unique: %v", catalog)
	}
}

func TestRenamedIdentifiersAreApplied(t *testing.T) {
	catalog := Default().Catalog()
	for old, current := range renamedDetectorIDs {
		if slices.Contains(catalog, old) {
			t.Errorf("old identifier %q is still in the catalog", old)
		}
		if !slices.Contains(catalog, current) {
			t.Errorf("renamed identifier %q is not in the catalog", current)
		}
	}
	for _, id := range []string{"netlify_personal_access_token", "airtable_personal_access_token", "digitalocean_personal_access_token", "stripe_api_key", "stripe_webhook_secret", "vault_token", "vault_token_file"} {
		if !slices.Contains(catalog, id) {
			t.Errorf("expected %q in the catalog", id)
		}
	}
}
