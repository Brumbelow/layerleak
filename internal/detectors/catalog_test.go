package detectors

import (
	"slices"
	"strings"
	"testing"
)

// TestDescribeCoversCatalog pins the read-only catalog description to the
// emitted identifiers: every Catalog() id is described exactly once, with a
// known strategy, a confidence tier and a short description, and no
// description outlives its identifier.
func TestDescribeCoversCatalog(t *testing.T) {
	set := Default()
	catalog := set.Catalog()
	infos := set.Describe()
	if len(infos) != len(catalog) {
		t.Fatalf("Describe() has %d entries, Catalog() has %d", len(infos), len(catalog))
	}
	known := make(map[string]bool, len(StrategyNames))
	for _, strategy := range StrategyNames {
		known[strategy.Name] = true
	}
	for index, info := range infos {
		if info.ID != catalog[index] {
			t.Fatalf("Describe()[%d].ID = %q, Catalog()[%d] = %q", index, info.ID, index, catalog[index])
		}
		if len(info.Strategies) == 0 || !slices.IsSorted(info.Strategies) {
			t.Errorf("%s: strategies = %v", info.ID, info.Strategies)
		}
		for _, strategy := range info.Strategies {
			if !known[strategy] {
				t.Errorf("%s: strategy %q is not in StrategyNames", info.ID, strategy)
			}
		}
		for _, tier := range strings.Split(info.Confidence, "/") {
			if tier != string(ConfidenceLow) && tier != string(ConfidenceMedium) && tier != string(ConfidenceHigh) {
				t.Errorf("%s: confidence %q is not a tier list", info.ID, info.Confidence)
			}
		}
		if strings.TrimSpace(info.Description) == "" || strings.ContainsAny(info.Description, "\n|") || len(info.Description) > 200 {
			t.Errorf("%s: description %q must be one short line without table separators", info.ID, info.Description)
		}
		if !strings.HasSuffix(info.Description, ".") {
			t.Errorf("%s: description %q should end with a period", info.ID, info.Description)
		}
	}
	for id := range detectorDescriptions {
		if !slices.Contains(catalog, id) {
			t.Errorf("description for %q has no detector in the catalog", id)
		}
	}
}

// TestDescribeMergesStrategiesAndTiers checks the ids several strategies
// share and the ids whose branches report different tiers.
func TestDescribeMergesStrategiesAndTiers(t *testing.T) {
	byID := make(map[string]Info)
	for _, info := range Default().Describe() {
		byID[info.ID] = info
	}
	cases := map[string]Info{
		"aws_secret_access_key":                {Confidence: "high", Strategies: []string{StrategyKeyValue, StrategyRegex}},
		"docker_auth_blob":                     {Confidence: "high", Strategies: []string{StrategyPathRegex, StrategyRegex}},
		"terraform_cloud_token":                {Confidence: "high", Strategies: []string{StrategyPathRegex, StrategyRegex}},
		"pem_private_key":                      {Confidence: "medium/high", Strategies: []string{StrategyPEM}},
		"aws_shared_credentials_access_key_id": {Confidence: "medium/high", Strategies: []string{StrategyStructuredFile}},
		"sensitive_file_keystore":              {Confidence: "low/medium", Strategies: []string{StrategyPathOnly}},
		"sensitive_file_private_key":           {Confidence: "medium", Strategies: []string{StrategyPathOnly}},
		"keyword_entropy":                      {Confidence: "low", Strategies: []string{StrategyEntropy}},
		"basic_auth_url":                       {Confidence: "high", Strategies: []string{StrategyURL}},
		"heroku_api_key":                       {Confidence: "high", Strategies: []string{StrategyContextual}},
		"telegram_bot_token":                   {Confidence: "high", Strategies: []string{StrategyShape}},
		"json_web_token":                       {Confidence: "medium", Strategies: []string{StrategyRegex}},
	}
	for id, want := range cases {
		got, ok := byID[id]
		if !ok {
			t.Fatalf("%s is missing from Describe()", id)
		}
		if got.Confidence != want.Confidence || !slices.Equal(got.Strategies, want.Strategies) {
			t.Errorf("%s: confidence %q strategies %v, want %q %v", id, got.Confidence, got.Strategies, want.Confidence, want.Strategies)
		}
	}
}

// TestDescribeFlagsUndescribedStrategies makes the fallback visible: a
// strategy without catalogEntries is listed as "custom" rather than dropped.
func TestDescribeFlagsUndescribedStrategies(t *testing.T) {
	set := Set{detectors: []Detector{undescribedDetector{}}}
	infos := set.Describe()
	if len(infos) != 1 || infos[0].ID != "undescribed_rule" || infos[0].Confidence != "" || !slices.Equal(infos[0].Strategies, []string{"custom"}) {
		t.Fatalf("Describe() = %+v", infos)
	}
}

type undescribedDetector struct{}

func (undescribedDetector) Name() string           { return "undescribed_rule" }
func (undescribedDetector) IDs() []string          { return singleID("undescribed_rule") }
func (undescribedDetector) Scan(ScanInput) []Match { return nil }
