package storage

import (
	"strings"
	"testing"
)

// TestParseKeywordDSNEdgeCases pins the libpq grammar corners: empty and
// quoted-empty values, escapes in both value forms, a trailing backslash and
// the exact error texts, none of which may quote a value.
func TestParseKeywordDSNEdgeCases(t *testing.T) {
	valid := map[string]map[string]string{
		"":                         {},
		"  \t\n ":                  {},
		"a=":                       {"a": ""},
		"a= b=x":                   {"a": "b=x"},
		"a='' b=x":                 {"a": "", "b": "x"},
		`a=x\ y`:                   {"a": "x y"},
		`a=x\`:                     {"a": `x\`},
		`a='x\'y' b=z`:             {"a": "x'y", "b": "z"},
		`a='\\'`:                   {"a": `\`},
		"a='x y'b=z":               {"a": "x y", "b": "z"},
		"A_1 = 'v' a_1=w":          {"A_1": "v", "a_1": "w"},
		"a=1 a=2":                  {"a": "2"},
		"host=h\fdbname=d\vport=1": {"host": "h", "dbname": "d", "port": "1"},
	}
	for input, want := range valid {
		pairs, err := parseKeywordDSN(input)
		if err != nil {
			t.Errorf("parseKeywordDSN(%q) error = %v", input, err)
			continue
		}
		if len(pairs) != len(want) {
			t.Errorf("parseKeywordDSN(%q) = %q, want %q", input, pairs, want)
			continue
		}
		for key, value := range want {
			if got, ok := pairs[key]; !ok || got != value {
				t.Errorf("parseKeywordDSN(%q)[%q] = %q, want %q", input, key, got, value)
			}
		}
	}

	invalid := map[string]string{
		"=x":                 `connection string key is missing`,
		"a=1 -b=2":           `connection string key is missing`,
		"host":               `connection string key "host" is not followed by '='`,
		"host x=1":           `connection string key "host" is not followed by '='`,
		"password='secret":   `connection string value for "password" has an unterminated quote`,
		`password='secret\'`: `connection string value for "password" has an unterminated quote`,
		`password='\`:        `connection string value for "password" has an unterminated quote`,
	}
	for input, want := range invalid {
		_, err := parseKeywordDSN(input)
		if err == nil || err.Error() != want {
			t.Errorf("parseKeywordDSN(%q) error = %v, want %q", input, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("parseKeywordDSN(%q) error quotes the value: %v", input, err)
		}
	}
}

// TestValidateDatabaseURLMessages pins each rejection's fixed text and the
// host and name sources validateDatabaseURL accepts.
func TestValidateDatabaseURLMessages(t *testing.T) {
	tests := map[string]string{
		"postgres://user:pw@localhost:5432/db":                    "",
		"postgresql://localhost/db":                               "",
		" POSTGRES ://localhost/db":                               "database url is invalid",
		"postgres:///db?host=/var/run/postgresql":                 "",
		"postgres:///db?hostaddr=127.0.0.1":                       "",
		"postgres://localhost?dbname=db":                          "",
		"postgres://localhost/?dbname=db":                         "",
		"mysql://localhost/db":                                    "database url must use postgres scheme",
		"localhost/db":                                            "database url must use postgres scheme",
		"postgres://user:pw@localhost:5432/db?x=%zz":              "database url is invalid",
		"postgres://user:pw%zz@localhost/db":                      "database url is invalid",
		"postgres:///db":                                          "database url host is required",
		"postgres:///db?host=%20":                                 "database url host is required",
		"postgres://localhost":                                    "database url name is required",
		"postgres://localhost/":                                   "database url name is required",
		"postgres://localhost/?dbname=%20":                        "database url name is required",
		"postgres://user:secret-value@localhost:5432/?sslmode=no": "database url name is required",
	}
	for input, want := range tests {
		err := validateDatabaseURL(input)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != want {
			t.Errorf("validateDatabaseURL(%q) = %q, want %q", input, got, want)
		}
	}
}
