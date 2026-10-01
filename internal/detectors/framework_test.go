package detectors

import (
	"encoding/base64"
	"strings"
	"testing"
)

var (
	testSHA512Digest = strings.Repeat("Ab1cD2eF3g", 8) + "hIjKl9" // 86
	testSHA256Digest = strings.Repeat("Ab1cD2eF3g", 4) + "hIj"    // 43
	testBcryptDigest = strings.Repeat("Ab1cD2eF3g", 5) + "hIj"    // 53
	testMD5Digest    = strings.Repeat("Ab1cD2eF3g", 2) + "hI"     // 22
	testDjangoKey    = "x!7$k9@p2#mQ8v%R4t^Y7w&Z1a*B3c(D5e-F6g_H8j=K0l+M2n)"
	testLaravelKey   = "base64:" + base64.StdEncoding.EncodeToString([]byte("Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK"))
)

// DET-34: OS and framework secrets.
func TestFrameworkSecretDetectors(t *testing.T) {
	set := Default()
	hex32 := "0123456789abcdef0123456789abcdef"
	hex128 := strings.Repeat(hex32, 4)
	tests := []struct {
		name       string
		input      ScanInput
		detector   string
		value      string
		confidence Confidence
	}{
		{name: "shadow sha512", input: ScanInput{Path: "/etc/shadow", Content: "root:$6$rounds=5000$saltsalt$" + testSHA512Digest + ":19000:0:99999:7:::\nbin:*:19000:0:99999:7:::\ndeploy:!:19000:0:99999:7:::\n"}, detector: "shadow_password_hash", value: "$6$rounds=5000$saltsalt$" + testSHA512Digest, confidence: ConfidenceHigh},
		{name: "shadow yescrypt", input: ScanInput{Path: "etc/shadow", Content: "root:$y$j9T$saltsaltsaltsaltsaltsalt$" + testSHA256Digest + ":19000:0:99999:7:::\n"}, detector: "shadow_password_hash", value: "$y$j9T$saltsaltsaltsaltsaltsalt$" + testSHA256Digest, confidence: ConfidenceHigh},
		{name: "shadow des", input: ScanInput{Path: "/etc/shadow", Content: "root:ab8ZhlNPCjcE2:19000:0:99999:7:::\n"}, detector: "shadow_password_hash", value: "ab8ZhlNPCjcE2", confidence: ConfidenceHigh},
		{name: "legacy passwd hash", input: ScanInput{Path: "/etc/passwd", Content: "root:$1$saltsalt$" + testMD5Digest + ":0:0:root:/root:/bin/bash\n"}, detector: "shadow_password_hash", value: "$1$saltsalt$" + testMD5Digest, confidence: ConfidenceHigh},
		{name: "htpasswd apr1", input: ScanInput{Path: "/etc/nginx/.htpasswd", Content: "admin:$apr1$saltsalt$" + testMD5Digest + "\n"}, detector: "htpasswd_password_hash", value: "$apr1$saltsalt$" + testMD5Digest, confidence: ConfidenceHigh},
		{name: "htpasswd bcrypt", input: ScanInput{Path: "/etc/apache2/htpasswd", Content: "admin:$2y$10$" + testBcryptDigest + "\n"}, detector: "htpasswd_password_hash", value: "$2y$10$" + testBcryptDigest, confidence: ConfidenceHigh},
		{name: "htpasswd sha", input: ScanInput{Path: "/srv/auth/users.htpasswd", Content: "admin:{SHA}Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6=\n"}, detector: "htpasswd_password_hash", value: "{SHA}Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6=", confidence: ConfidenceHigh},
		{name: "usermod hash in history", input: ScanInput{Key: "history[1].created_by", Content: "/bin/sh -c usermod -p '$6$saltsalt$" + testSHA512Digest + "' root"}, detector: "password_hash", value: "$6$saltsalt$" + testSHA512Digest, confidence: ConfidenceMedium},
		{name: "bcrypt in yaml", input: ScanInput{Path: "/app/users.yaml", Content: "admin:\n  hash: $2b$12$" + testBcryptDigest + "\n"}, detector: "password_hash", value: "$2b$12$" + testBcryptDigest, confidence: ConfidenceMedium},
		{name: "sha crypt in cloud-init", input: ScanInput{Path: "/etc/cloud/cloud.cfg.d/99-users.cfg", Content: "users:\n  - name: ops\n    passwd: $5$saltsalt$" + testSHA256Digest + "\n"}, detector: "password_hash", value: "$5$saltsalt$" + testSHA256Digest, confidence: ConfidenceMedium},
		{name: "laravel app key", input: ScanInput{Path: "/var/www/.env", Content: "APP_NAME=Laravel\nAPP_KEY=" + testLaravelKey + "\n"}, detector: "laravel_app_key", value: testLaravelKey, confidence: ConfidenceHigh},
		{name: "laravel app key in env", input: ScanInput{Key: "APP_KEY", Content: "APP_KEY=" + testLaravelKey}, detector: "laravel_app_key", value: testLaravelKey, confidence: ConfidenceHigh},
		{name: "django secret key", input: ScanInput{Path: "/app/settings.py", Content: "SECRET_KEY = 'django-insecure-" + testDjangoKey + "'\n"}, detector: "framework_secret_key", value: "django-insecure-" + testDjangoKey, confidence: ConfidenceHigh},
		{name: "flask config secret key", input: ScanInput{Path: "/app/app.py", Content: "app.config[\"SECRET_KEY\"] = \"" + testDjangoKey + "\"\n"}, detector: "framework_secret_key", value: testDjangoKey, confidence: ConfidenceHigh},
		{name: "flask attribute secret key", input: ScanInput{Path: "/app/app.py", Content: "app.secret_key = '" + testDjangoKey + "'\n"}, detector: "framework_secret_key", value: testDjangoKey, confidence: ConfidenceHigh},
		{name: "dotenv secret key", input: ScanInput{Path: "/app/.env", Content: "DJANGO_SECRET_KEY=" + testDjangoKey + "\n"}, detector: "framework_secret_key", value: testDjangoKey, confidence: ConfidenceHigh},
		{name: "rails master key", input: ScanInput{Path: "/app/config/master.key", Content: hex32 + "\n"}, detector: "rails_master_key", value: hex32, confidence: ConfidenceHigh},
		{name: "rails credentials key", input: ScanInput{Path: "/app/config/credentials/production.key", Content: hex32}, detector: "rails_master_key", value: hex32, confidence: ConfidenceHigh},
		{name: "rails secret key base", input: ScanInput{Path: "/app/config/secrets.yml", Content: "production:\n  secret_key_base: " + hex128 + "\n"}, detector: "rails_secret_key_base", value: hex128, confidence: ConfidenceHigh},
		{name: "rails secret key base env", input: ScanInput{Key: "SECRET_KEY_BASE", Content: "SECRET_KEY_BASE=" + hex128}, detector: "rails_secret_key_base", value: hex128, confidence: ConfidenceHigh},
		{name: "wordpress auth salt", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define('AUTH_KEY',         '" + testDjangoKey + "');\n"}, detector: "wordpress_auth_salt", value: testDjangoKey, confidence: ConfidenceHigh},
		{name: "wordpress db password", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define( 'DB_PASSWORD', 'Sup3rS3cretPwXyz' );\n"}, detector: "php_define_password", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
		{name: "php url signing secret constant", input: ScanInput{Path: "/app/config.php", Content: "define('URL_SIGNING_SECRET', 'Xk9fL2mQ8vR4tY7wZ1aB');\n"}, detector: "php_define_password", value: "Xk9fL2mQ8vR4tY7wZ1aB", confidence: ConfidenceHigh},
		{name: "php api key constant", input: ScanInput{Path: "/app/config.php", Content: "define(\"STRIPE_API_KEY_LIVE\", \"Xk9fL2mQ8vR4tY7wZ1aB\");\n"}, detector: "php_define_password", value: "Xk9fL2mQ8vR4tY7wZ1aB", confidence: ConfidenceHigh},
		{name: "jenkins credentials password element", input: ScanInput{Path: "/var/jenkins_home/credentials.xml", Content: "<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>\n  <username>deploy</username>\n  <password>Sup3rS3cretPwXyz</password>\n</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>\n"}, detector: "xml_password_element", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
		{name: "tomcat users attribute", input: ScanInput{Path: "/usr/local/tomcat/conf/tomcat-users.xml", Content: "<tomcat-users>\n  <user username=\"admin\" password=\"Sup3rS3cretPwXyz\" roles=\"manager-gui\"/>\n</tomcat-users>\n"}, detector: "xml_password_attribute", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
		{name: "tomcat jndi resource attribute", input: ScanInput{Path: "/usr/local/tomcat/conf/server.xml", Content: "<Resource name=\"jdbc/app\" username=\"app\" password=\"Sup3rS3cretPwXyz\" driverClassName=\"org.postgresql.Driver\"/>\n"}, detector: "xml_password_attribute", value: "Sup3rS3cretPwXyz", confidence: ConfidenceHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			match, ok := findDetectorMatch(matches, tt.detector)
			if !ok {
				t.Fatalf("expected %s in %#v", tt.detector, matches)
			}
			if match.Value != tt.value {
				t.Fatalf("match.Value = %q, want %q", match.Value, tt.value)
			}
			if match.Confidence != tt.confidence {
				t.Fatalf("match.Confidence = %q, want %q", match.Confidence, tt.confidence)
			}
			if tt.input.Content[match.Start:match.End] != match.Value {
				t.Fatalf("span [%d:%d] does not address the value", match.Start, match.End)
			}
		})
	}
}

func TestFrameworkSecretDetectorsRejectReferencesAndPlaceholders(t *testing.T) {
	set := Default()
	tests := []struct {
		name     string
		input    ScanInput
		detector string
	}{
		{name: "passwd with shadowed entries", input: ScanInput{Path: "/etc/passwd", Content: "root:x:0:0:root:/root:/bin/bash\nnobody:*:65534:65534::/nonexistent:/usr/sbin/nologin\n"}, detector: "shadow_password_hash"},
		{name: "locked shadow entries", input: ScanInput{Path: "/etc/shadow", Content: "root:!:19000:0:99999:7:::\nbin:*:19000:0:99999:7:::\nsync:!!:19000:0:99999:7:::\n"}, detector: "shadow_password_hash"},
		{name: "sha512 hash with a truncated digest", input: ScanInput{Content: "$6$saltsalt$" + strings.Repeat("Ab1cD2eF3g", 5)}, detector: "password_hash"},
		{name: "sha with the wrong length", input: ScanInput{Content: "{SHA}Xk9fL2mQ8vR4tY7wZ1aB3cD5eF6gH8jK0lM2n="}, detector: "password_hash"},
		{name: "shell parameters are not a hash", input: ScanInput{Content: "echo $1$2 && cat $5$6 | $y$ok"}, detector: "password_hash"},
		{name: "laravel placeholder", input: ScanInput{Path: "/var/www/.env", Content: "APP_KEY=base64:" + base64.StdEncoding.EncodeToString([]byte("short")) + "\n"}, detector: "laravel_app_key"},
		{name: "laravel empty key", input: ScanInput{Path: "/var/www/.env.example", Content: "APP_KEY=\n"}, detector: "laravel_app_key"},
		{name: "django secret from environment", input: ScanInput{Path: "/app/settings.py", Content: "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'unsafe-default-for-development-only-value')\n"}, detector: "framework_secret_key"},
		{name: "django secret template reference", input: ScanInput{Path: "/app/settings.py", Content: "SECRET_KEY = '${DJANGO_SECRET_KEY_FROM_THE_VAULT_PLEASE}'\n"}, detector: "framework_secret_key"},
		{name: "aws secret key is a different key", input: ScanInput{Path: "/app/settings.py", Content: "AWS_SECRET_KEY = '" + testDjangoKey + "'\n"}, detector: "framework_secret_key"},
		{name: "secret key base is a different key", input: ScanInput{Path: "/app/settings.py", Content: "SECRET_KEY_BASE = '" + testDjangoKey + "'\n"}, detector: "framework_secret_key"},
		{name: "rails secret key base erb reference", input: ScanInput{Path: "/app/config/secrets.yml", Content: "production:\n  secret_key_base: <%= ENV[\"SECRET_KEY_BASE\"] %>\n"}, detector: "rails_secret_key_base"},
		{name: "master key outside config", input: ScanInput{Path: "/app/master.key", Content: "0123456789abcdef0123456789abcdef\n"}, detector: "rails_master_key"},
		{name: "master key with extra content", input: ScanInput{Path: "/app/config/master.key", Content: "0123456789abcdef0123456789abcdef\nextra\n"}, detector: "rails_master_key"},
		{name: "wordpress sample salts", input: ScanInput{Path: "/var/www/html/wp-config-sample.php", Content: "define( 'AUTH_KEY',         'put your unique phrase here' );\n"}, detector: "wordpress_auth_salt"},
		{name: "wordpress sample db password", input: ScanInput{Path: "/var/www/html/wp-config-sample.php", Content: "define( 'DB_PASSWORD', 'password_here' );\n"}, detector: "php_define_password"},
		{name: "php constant from getenv", input: ScanInput{Path: "/app/config.php", Content: "define('DB_PASSWORD', getenv('DB_PASSWORD'));\n"}, detector: "php_define_password"},
		{name: "php ttl constant", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define('API_TOKEN_TTL', '3600seconds');\n"}, detector: "php_define_password"},
		{name: "php key path constant", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define('JWT_SECRET_KEY_PATH', 'storage/keys/jwt.pem');\n"}, detector: "php_define_password"},
		{name: "php salt file constant", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define('SECRET_SALT_FILE', 'config/salt.txt');\n"}, detector: "php_define_password"},
		{name: "php expiry constant", input: ScanInput{Path: "/var/www/html/wp-config.php", Content: "define('TOKEN_EXPIRY', '86400000');\n"}, detector: "php_define_password"},
		{name: "php bare file name constant", input: ScanInput{Path: "/app/config.php", Content: "define('DB_PASSWORD', 'secrets.json');\n"}, detector: "php_define_password"},
		{name: "php relative path constant", input: ScanInput{Path: "/app/config.php", Content: "define('PATH_TO_SECRET', 'storage/app/secret.key');\n"}, detector: "php_define_password"},
		{name: "tomcat commented sample users", input: ScanInput{Path: "/usr/local/tomcat/conf/tomcat-users.xml", Content: "<tomcat-users>\n<!--\n  <user username=\"tomcat\" password=\"tomcat\" roles=\"tomcat\"/>\n  <user username=\"both\" password=\"tomcat\" roles=\"tomcat,role1\"/>\n-->\n</tomcat-users>\n"}, detector: "xml_password_attribute"},
		{name: "android boolean password attribute", input: ScanInput{Path: "/app/res/layout/login.xml", Content: "<EditText android:id=\"@+id/pwd\" android:password=\"true\" android:inputType=\"textPassword\"/>\n"}, detector: "xml_password_attribute"},
		{name: "keyword password attributes", input: ScanInput{Path: "/app/users.xml", Content: "<field name=\"pwd\" password=\"none\"/><user password=\"required\"/><x password=\"optional\"/><y password=\"FALSE\"/><z passwd=\"null\"/>\n"}, detector: "xml_password_attribute"},
		{name: "short password attribute", input: ScanInput{Path: "/app/users.xml", Content: "<user username=\"admin\" password=\"ab1cd\"/>\n"}, detector: "xml_password_attribute"},
		{name: "keyword password element", input: ScanInput{Path: "/app/config.xml", Content: "<password>required</password>\n"}, detector: "xml_password_element"},
		{name: "tomcat must-be-changed placeholder", input: ScanInput{Path: "/usr/local/tomcat/conf/tomcat-users.xml", Content: "<user username=\"admin\" password=\"<must-be-changed>\" roles=\"manager-gui\"/>\n"}, detector: "xml_password_attribute"},
		{name: "maven property reference in element", input: ScanInput{Path: "/app/pom.xml", Content: "<password>${env.NEXUS_PASSWORD}</password>"}, detector: "xml_password_element"},
		{name: "commented password element", input: ScanInput{Path: "/app/context.xml", Content: "<!-- <password>Sup3rS3cretPwXyz</password> -->\n<password>Oth3rS3cretPwXyz</password>\n"}, detector: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := set.Scan(tt.input)
			if tt.detector == "" {
				// Only the uncommented element is reported.
				if len(matches) != 1 || matches[0].Detector != "xml_password_element" || matches[0].Value != "Oth3rS3cretPwXyz" {
					t.Fatalf("matches = %#v", matches)
				}
				return
			}
			for _, match := range matches {
				if match.Detector == tt.detector {
					t.Fatalf("unexpected %s match: %#v", tt.detector, match)
				}
			}
		})
	}
}

// A hash inside a password file is reported once, by the file reader.
func TestShadowHashIsReportedOnceAtHighConfidence(t *testing.T) {
	matches := Default().Scan(ScanInput{Path: "/etc/shadow", Content: "root:$6$saltsalt$" + testSHA512Digest + ":19000:0:99999:7:::\n"})
	if len(matches) != 1 || matches[0].Detector != "shadow_password_hash" || matches[0].Confidence != ConfidenceHigh {
		t.Fatalf("matches = %#v", matches)
	}
}

// Maven settings.xml keeps its dedicated id when the generic XML element
// rule also matches.
func TestMavenSettingsPasswordKeepsItsIdentifier(t *testing.T) {
	matches := Default().Scan(ScanInput{Path: "/root/.m2/settings.xml", Content: "<servers><server><id>nexus</id><password>Sup3rS3cretPwXyz</password></server></servers>"})
	if len(matches) != 1 || matches[0].Detector != "maven_settings_password" {
		t.Fatalf("matches = %#v", matches)
	}
}
