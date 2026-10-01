package detectors

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// PathDetector is implemented by strategies that can report an artifact from
// its path alone: a binary or oversize file the scanner cannot read (LAY-12).
type PathDetector interface {
	Detector
	ScanPath(filePath string) []Match
}

// ScanPath reports the path-only matches for an artifact. Each match covers
// the whole path (Value is the path and the span is [0, len(path))) so the
// findings normalizer can address it with the path as its content; the
// scanner then drops the value-derived fields, because a path-only finding
// has no secret value to redact or fingerprint. The result is sorted by
// detector id so two scans of one path agree.
func (s Set) ScanPath(filePath string) []Match {
	matches := make([]Match, 0, 1)
	for _, detector := range s.detectors {
		pathDetector, ok := detector.(PathDetector)
		if !ok {
			continue
		}
		matches = append(matches, pathDetector.ScanPath(filePath)...)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Detector < matches[j].Detector
	})
	return matches
}

// The sensitive_file family: one id per kind of artifact, so a consumer can
// tell a keystore from a credential store without parsing the path.
const (
	sensitiveFilePrivateKey       = "sensitive_file_private_key"
	sensitiveFileKeystore         = "sensitive_file_keystore"
	sensitiveFilePasswordDatabase = "sensitive_file_password_database"
	sensitiveFileCredentialStore  = "sensitive_file_credential_store"
	sensitiveFileGPGKeyring       = "sensitive_file_gpg_keyring"
)

var (
	// sshPrivateKeyNameExpression matches id_rsa, id_ed25519_sk, id_rsa_deploy
	// and the like; the matching .pub files are excluded by name below.
	sshPrivateKeyNameExpression = regexp.MustCompile(`^id_(?:rsa|dsa|ecdsa|ed25519)(?:[_.-][a-z0-9_.-]*)?$`)
	credentialStoreNames        = map[string]struct{}{".netrc": {}, "_netrc": {}, ".pgpass": {}, ".git-credentials": {}}
	credentialStoreSuffixes     = []string{".aws/credentials", ".docker/config.json"}
)

// sensitiveFileDetector reports sensitive artifacts by path. It never
// matches content (Scan returns nothing): the scanner calls ScanPath only for
// artifacts it could not read, so a readable key file is judged by the
// content rules alone and is never reported twice.
type sensitiveFileDetector struct{}

func (sensitiveFileDetector) Name() string {
	return "sensitive_file"
}

func (sensitiveFileDetector) IDs() []string {
	return []string{sensitiveFilePrivateKey, sensitiveFileKeystore, sensitiveFilePasswordDatabase, sensitiveFileCredentialStore, sensitiveFileGPGKeyring}
}

func (sensitiveFileDetector) Scan(ScanInput) []Match {
	return nil
}

func (sensitiveFileDetector) ScanPath(filePath string) []Match {
	id, confidence, ok := classifySensitiveFile(filePath)
	if !ok {
		return nil
	}
	return []Match{{
		Detector:   id,
		Value:      filePath,
		Start:      0,
		End:        len(filePath),
		Confidence: confidence,
		Priority:   priorityStructured,
	}}
}

// classifySensitiveFile names the kind of sensitive artifact a path denotes.
// Confidence is capped at medium because the content was not seen: a private
// key file, PKCS#12 bundle, KeePass database, GnuPG secret keyring or a
// credential store too large or too binary to read is almost always key
// material (medium); Java keystores are as often truststores (low).
// Truststores and cacerts bundles hold public certificates and are not
// reported.
func classifySensitiveFile(filePath string) (string, Confidence, bool) {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(filePath, "\\", "/")))
	if normalized == "" {
		return "", "", false
	}
	base := path.Base(normalized)
	switch {
	case sshPrivateKeyNameExpression.MatchString(base) && !strings.HasSuffix(base, ".pub"):
		return sensitiveFilePrivateKey, ConfidenceMedium, true
	case base == "secring.gpg", path.Base(path.Dir(normalized)) == "private-keys-v1.d" && strings.HasSuffix(base, ".key"):
		return sensitiveFileGPGKeyring, ConfidenceMedium, true
	case strings.HasSuffix(base, ".kdbx"):
		return sensitiveFilePasswordDatabase, ConfidenceMedium, true
	}
	if _, ok := credentialStoreNames[base]; ok {
		return sensitiveFileCredentialStore, ConfidenceMedium, true
	}
	for _, suffix := range credentialStoreSuffixes {
		if normalized == suffix || strings.HasSuffix(normalized, "/"+suffix) {
			return sensitiveFileCredentialStore, ConfidenceMedium, true
		}
	}
	if strings.Contains(base, "trust") || base == "cacerts" {
		return "", "", false
	}
	switch path.Ext(base) {
	case ".p12", ".pfx":
		return sensitiveFileKeystore, ConfidenceMedium, true
	case ".jks", ".keystore":
		return sensitiveFileKeystore, ConfidenceLow, true
	}
	return "", "", false
}
