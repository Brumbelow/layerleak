package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var xmlPathExpression = regexp.MustCompile(`\.xml$`)

// frameworkSecretDetectors cover the operating-system and web-framework
// secrets that get baked into images (DET-34): /etc/shadow and .htpasswd
// password hashes (and modular-crypt hashes anywhere, such as `usermod -p`
// in image history), Laravel APP_KEY, Django/Flask SECRET_KEY values with
// punctuation, Rails master.key files and secret_key_base, WordPress salts
// and define()d passwords, and XML <password> elements and attributes
// (Jenkins credentials.xml, Tomcat tomcat-users.xml and server.xml).
func frameworkSecretDetectors() []Detector {
	// hashLine is the "user:hash" grammar shared by shadow and htpasswd files:
	// modular-crypt ($id$...), {SHA}/{SSHA} and 13-character DES hashes; "x",
	// "*" and "!" (locked) never match.
	const hashLine = `(?m)^[^:\s#]+:((?:\$[A-Za-z0-9]+\$[^:\s]{8,}|\{S?SHA\}[A-Za-z0-9+/=]{28,}|[A-Za-z0-9./]{13}))`
	return []Detector{
		// A password hash outside a password file (cloud-init, kickstart,
		// Ansible vars, `usermod -p` in a RUN line) is crackable key material
		// but may also be documentation, so the bare shape is medium; the
		// path-gated readers below report the same span at high and win.
		newRegexDetector("password_hash", regexp.MustCompile(`(?:\$(?:1|apr1)\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}|\$[56]\$(?:rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43,86}|\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}|\$g?y\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{43}|\{S?SHA\}[A-Za-z0-9+/=]{28,})\b`), 0, ConfidenceMedium, looksLikeCryptHash).requiring("$1$", "$apr1$", "$5$", "$6$", "$2a$", "$2b$", "$2x$", "$2y$", "$y$", "$gy$", "{SHA}", "{SSHA}"),
		// The second field of a shadow (or legacy passwd) entry is the hash of
		// a real account: high.
		newPathRegexDetector("shadow_password_hash", regexp.MustCompile(`(^|/)etc/(?:shadow|gshadow|shadow-|gshadow-|passwd|passwd-|master\.passwd)$`), regexp.MustCompile(hashLine+`:`), 1, ConfidenceHigh, nil),
		newPathRegexDetector("htpasswd_password_hash", regexp.MustCompile(`(^|/)(?:\.htpasswd|htpasswd|[^/]+\.htpasswd)$`), regexp.MustCompile(hashLine+`\s*$`), 1, ConfidenceHigh, nil),
		// Laravel writes APP_KEY=base64:<key>; the key must decode to the 16
		// or 32 bytes AES expects, which rules out placeholders: high.
		newRegexDetector("laravel_app_key", regexp.MustCompile(assignedValuePattern(`app_key`, `base64:[a-z0-9+/]{20,}={0,2}`, ``)), 1, ConfidenceHigh, looksLikeLaravelAppKey).onLoweredContent(),
		// Django and Flask SECRET_KEY (also DJANGO_/FLASK_/JWT_ prefixed and
		// app.secret_key / app.config["SECRET_KEY"]). The generated values mix
		// letters, digits and punctuation, so the value runs to the closing
		// quote or whitespace and an entropy check rejects placeholders.
		// aws_secret_key and secret_key_base are different keys and excluded.
		newRegexDetector("framework_secret_key", regexp.MustCompile(`(?:^|[^a-z0-9_])(?:django_|flask_|jwt_|app\.)?secret_key["'\]]*\s*(?:=|:)\s*["']?([^"'\s]{32,})`), 1, ConfidenceHigh, looksLikeFrameworkSecretKey).onLoweredContent().requiring("secret_key"),
		// config/master.key and config/credentials/<env>.key hold one bare
		// 32-hex key and nothing else: high.
		newPathRegexDetector("rails_master_key", regexp.MustCompile(`(^|/)config/(?:master|credentials/[^/]+)\.key$`), regexp.MustCompile(`(?s)^\s*([0-9a-f]{32})\s*$`), 1, ConfidenceHigh, nil),
		// `rails secret` prints 128 hex characters; older apps used 64.
		newRegexDetector("rails_secret_key_base", regexp.MustCompile(assignedValuePattern(`secret_key_base`, `[0-9a-f]{64,128}`, `\b`)), 1, ConfidenceHigh, nil).onLoweredContent(),
		// wp-config.php salts: eight define()d constants of 64 random
		// characters. The placeholder "put your unique phrase here" fails the
		// entropy check.
		newRegexDetector("wordpress_auth_salt", regexp.MustCompile(`define\(\s*["'](?:auth_key|secure_auth_key|logged_in_key|nonce_key|auth_salt|secure_auth_salt|logged_in_salt|nonce_salt)["']\s*,\s*["']([^"']{32,})["']`), 1, ConfidenceHigh, looksLikeFrameworkSecretKey).onLoweredContent(),
		// define('DB_PASSWORD', '...') and any other password/secret/key/token
		// constant: an explicit literal credential, high. Configuration
		// references and the WordPress "password_here" sample are rejected.
		newRegexDetector("php_define_password", regexp.MustCompile(`define\(\s*["'][a-z0-9_]*(?:password|passwd|secret|api_?key|token)[a-z0-9_]*["']\s*,\s*["']([^"'\s]{8,})["']`), 1, ConfidenceHigh, looksLikePHPDefinedPassword).onLoweredContent(),
		// <password>...</password> elements (Jenkins credentials.xml, Tomcat
		// and Maven descriptors) and password="..." attributes (tomcat-users.xml
		// users, server.xml JNDI resources). Matches inside <!-- --> comments,
		// where Tomcat ships its sample users, are skipped.
		newPathRegexDetector("xml_password_element", xmlPathExpression, regexp.MustCompile(`(?is)<(?:password|passphrase)>\s*([^<\s]{6,})\s*</(?:password|passphrase)>`), 1, ConfidenceHigh, looksLikeLiteralPassword).skipping(insideXMLComment),
		newPathRegexDetector("xml_password_attribute", xmlPathExpression, regexp.MustCompile(`(?i)\b(?:password|passwd)\s*=\s*"([^"\s]{4,})"`), 1, ConfidenceHigh, looksLikeLiteralPassword).skipping(insideXMLComment),
	}
}

// looksLikeCryptHash enforces the digest lengths the modular-crypt ids fix:
// sha256-crypt ($5$) is 43 characters, sha512-crypt ($6$) 86, {SHA} exactly
// 28 and {SSHA} at least 28. The regular expression already fixes the other
// families.
func looksLikeCryptHash(value string) bool {
	switch {
	case strings.HasPrefix(value, "{SHA}"):
		return len(value) == len("{SHA}")+28
	case strings.HasPrefix(value, "{SSHA}"):
		return len(value) >= len("{SSHA}")+28
	}
	segments := strings.Split(value, "$")
	if len(segments) < 4 {
		return false
	}
	digest := segments[len(segments)-1]
	switch segments[1] {
	case "5":
		return len(digest) == 43
	case "6":
		return len(digest) == 86
	default:
		return true
	}
}

// looksLikeLaravelAppKey accepts base64:<key> when the key decodes to 16 or
// 32 bytes (AES-128-CBC or AES-256-CBC).
func looksLikeLaravelAppKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "base64:"))
	return err == nil && (len(decoded) == 16 || len(decoded) == 32)
}

// looksLikeFrameworkSecretKey rejects configuration references and
// low-entropy placeholders; generated framework keys mix several character
// classes and clear the entropy floor easily.
func looksLikeFrameworkSecretKey(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 32 || !isPrintableText(trimmed) {
		return false
	}
	if strings.HasPrefix(trimmed, "$") || strings.HasPrefix(trimmed, "<") {
		return false
	}
	for _, marker := range []string{"${", "{{", "}}", "%("} {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return passesEntropy(trimmed)
}

// looksLikePHPDefinedPassword accepts literal passwords in define() calls
// and rejects paths, references and the WordPress "password_here" sample.
func looksLikePHPDefinedPassword(value string) bool {
	if !looksLikeLiteralPassword(value) || strings.HasPrefix(value, "/") {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.HasSuffix(lower, "_here") && lower != "password"
}

// insideXMLComment reports whether offset start lies inside an unterminated
// <!-- comment.
func insideXMLComment(content string, start int) bool {
	open := strings.LastIndex(content[:start], "<!--")
	if open < 0 {
		return false
	}
	return !strings.Contains(content[open:start], "-->")
}
