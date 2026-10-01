package detectors

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Info describes one catalog identifier for `layerleak detectors list` and
// docs/detectors.md. It is read-only metadata assembled from the registered
// strategies; it never changes what the set matches.
type Info struct {
	// ID is the identifier findings carry in detector_name.
	ID string `json:"id"`
	// Confidence is the tier a match carries before path and key context
	// adjust it. When several strategies or branches emit the same id at
	// different tiers the tiers are joined low to high, for example
	// "medium/high".
	Confidence string `json:"confidence"`
	// Strategies names the matching strategies that can emit the id, sorted;
	// see StrategyNames for the vocabulary.
	Strategies []string `json:"strategies"`
	// Description is one short factual sentence.
	Description string `json:"description"`
}

// Strategy names, in the order docs/detectors.md explains them.
const (
	// StrategyRegex: a value pattern matched anywhere in the content, with a
	// literal prefilter.
	StrategyRegex = "regex"
	// StrategyPathRegex: a value pattern that only runs on files whose path
	// matches a known configuration or credential file.
	StrategyPathRegex = "path_regex"
	// StrategyKeyValue: a value pattern gated on the variable, label or key
	// name the value is assigned to.
	StrategyKeyValue = "key_value"
	// StrategyContextual: a vendor token found by its prefixed form or by an
	// assignment to a vendor-named key.
	StrategyContextual = "contextual"
	// StrategyURL: a URL whose userinfo carries a password.
	StrategyURL = "url"
	// StrategyPEM: PEM armour parsing.
	StrategyPEM = "pem"
	// StrategyStructuredFile: a reader for one credential file format
	// (.aws/credentials, .git-credentials, .pgpass).
	StrategyStructuredFile = "structured_file"
	// StrategyShape: a token shape checked by a structural validator.
	StrategyShape = "shape"
	// StrategyPathOnly: a file reported by its path when its content cannot
	// be read (binary or oversize).
	StrategyPathOnly = "path_only"
	// StrategyEntropy: a keyword-gated entropy heuristic.
	StrategyEntropy = "entropy"
)

// StrategyNames lists every strategy with a short explanation, in
// documentation order.
var StrategyNames = []struct {
	Name        string
	Explanation string
}{
	{StrategyRegex, "A value pattern matched anywhere in the content, behind a literal prefilter."},
	{StrategyPathRegex, "A value pattern that only runs on files whose path names a known configuration or credential file."},
	{StrategyKeyValue, "A value pattern gated on the environment variable, label or key name the value is assigned to."},
	{StrategyContextual, "A vendor token found either by its prefixed form or by an assignment to a vendor-named key."},
	{StrategyURL, "A URL whose userinfo carries a password, with host and scheme checks."},
	{StrategyPEM, "PEM armour parsing for private key blocks."},
	{StrategyStructuredFile, "A reader for one credential file format (.aws/credentials, .git-credentials, .pgpass)."},
	{StrategyShape, "A token shape checked by a structural validator such as an embedded identifier or checksum."},
	{StrategyPathOnly, "A file reported by its path alone when its content cannot be read (binary or oversize); the finding has no value."},
	{StrategyEntropy, "A keyword-gated entropy heuristic over assigned values."},
}

// catalogEntry is one identifier a strategy can emit, the strategy's name and
// the base confidence of the matches it reports under that id.
type catalogEntry struct {
	id         string
	strategy   string
	confidence Confidence
}

// cataloguer is implemented by every registered strategy so Describe can
// report how each identifier is matched. A strategy with several branches at
// different tiers lists one entry per tier.
type cataloguer interface {
	catalogEntries() []catalogEntry
}

func singleEntry(id, strategy string, confidence Confidence) []catalogEntry {
	return []catalogEntry{{id: id, strategy: strategy, confidence: confidence}}
}

func (d regexDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.name, StrategyRegex, d.base)
}

func (d pathRegexDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.name, StrategyPathRegex, d.base)
}

func (d keyValueDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.name, StrategyKeyValue, d.base)
}

func (d contextualTokenDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.name, StrategyContextual, ConfidenceHigh)
}

func (d credentialedURLDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.name, StrategyURL, ConfidenceHigh)
}

// A PEM block with a body is high; a header with no body is medium.
func (d pemPrivateKeyDetector) catalogEntries() []catalogEntry {
	return []catalogEntry{
		{id: d.Name(), strategy: StrategyPEM, confidence: ConfidenceMedium},
		{id: d.Name(), strategy: StrategyPEM, confidence: ConfidenceHigh},
	}
}

// Access key ids and session tokens are medium unless their profile also
// holds a secret; secret access keys are always high.
func (awsSharedCredentialsDetector) catalogEntries() []catalogEntry {
	return []catalogEntry{
		{id: "aws_shared_credentials_access_key_id", strategy: StrategyStructuredFile, confidence: ConfidenceMedium},
		{id: "aws_shared_credentials_access_key_id", strategy: StrategyStructuredFile, confidence: ConfidenceHigh},
		{id: "aws_shared_credentials_secret_access_key", strategy: StrategyStructuredFile, confidence: ConfidenceHigh},
		{id: "aws_shared_credentials_session_token", strategy: StrategyStructuredFile, confidence: ConfidenceMedium},
		{id: "aws_shared_credentials_session_token", strategy: StrategyStructuredFile, confidence: ConfidenceHigh},
	}
}

func (gitCredentialsDetector) catalogEntries() []catalogEntry {
	return singleEntry("git_credentials_password", StrategyStructuredFile, ConfidenceHigh)
}

func (d pgpassDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.Name(), StrategyStructuredFile, ConfidenceHigh)
}

func (d discordBotTokenDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.Name(), StrategyShape, ConfidenceHigh)
}

func (d telegramBotTokenDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.Name(), StrategyShape, ConfidenceHigh)
}

// Path-only confidence is capped at medium because the content was not seen;
// Java keystores are as often truststores, so .jks/.keystore are low.
func (sensitiveFileDetector) catalogEntries() []catalogEntry {
	return []catalogEntry{
		{id: sensitiveFilePrivateKey, strategy: StrategyPathOnly, confidence: ConfidenceMedium},
		{id: sensitiveFileKeystore, strategy: StrategyPathOnly, confidence: ConfidenceLow},
		{id: sensitiveFileKeystore, strategy: StrategyPathOnly, confidence: ConfidenceMedium},
		{id: sensitiveFilePasswordDatabase, strategy: StrategyPathOnly, confidence: ConfidenceMedium},
		{id: sensitiveFileCredentialStore, strategy: StrategyPathOnly, confidence: ConfidenceMedium},
		{id: sensitiveFileGPGKeyring, strategy: StrategyPathOnly, confidence: ConfidenceMedium},
	}
}

func (d contextEntropyDetector) catalogEntries() []catalogEntry {
	return singleEntry(d.Name(), StrategyEntropy, ConfidenceLow)
}

// CatalogDigest identifies the set's public identifier list for
// scanner.detector_set_version: "sha256:" followed by the lowercase hex
// SHA-256 of Catalog() joined by newlines. It changes whenever an identifier
// is added, removed or renamed, never with the order strategies are
// registered in, and like Describe it never changes what the set matches.
func (s Set) CatalogDigest() string {
	sum := sha256.Sum256([]byte(strings.Join(s.Catalog(), "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Describe returns one Info per catalog identifier, sorted by id, merging
// the strategies and base confidence tiers of every strategy that emits it.
// The ids are exactly Catalog(); a strategy that does not describe itself
// is reported with the strategy name "custom" and no confidence so the
// omission is visible rather than silent.
func (s Set) Describe() []Info {
	strategies := make(map[string]map[string]struct{})
	confidences := make(map[string]map[Confidence]struct{})
	record := func(id, strategy string, confidence Confidence) {
		if strategies[id] == nil {
			strategies[id] = make(map[string]struct{})
			confidences[id] = make(map[Confidence]struct{})
		}
		strategies[id][strategy] = struct{}{}
		if confidence != "" {
			confidences[id][confidence] = struct{}{}
		}
	}
	for _, detector := range s.detectors {
		described, ok := detector.(cataloguer)
		if !ok {
			for _, id := range detector.IDs() {
				record(id, "custom", "")
			}
			continue
		}
		for _, entry := range described.catalogEntries() {
			record(entry.id, entry.strategy, entry.confidence)
		}
	}

	infos := make([]Info, 0, len(strategies))
	for _, id := range s.Catalog() {
		names := make([]string, 0, len(strategies[id]))
		for name := range strategies[id] {
			names = append(names, name)
		}
		sort.Strings(names)
		infos = append(infos, Info{
			ID:          id,
			Confidence:  joinConfidences(confidences[id]),
			Strategies:  names,
			Description: detectorDescriptions[id],
		})
	}
	return infos
}

// joinConfidences renders the tiers low to high, "low/medium" style.
func joinConfidences(tiers map[Confidence]struct{}) string {
	parts := make([]string, 0, len(tiers))
	for _, tier := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		if _, ok := tiers[tier]; ok {
			parts = append(parts, string(tier))
		}
	}
	return strings.Join(parts, "/")
}
