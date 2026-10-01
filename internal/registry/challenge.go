package registry

import (
	"fmt"
	"strings"
)

// authChallenge is one RFC 7235 challenge: a scheme followed by auth-params.
type authChallenge struct {
	Scheme string
	Params map[string]string
}

// parseBearerChallenges selects the first Bearer challenge across all
// WWW-Authenticate headers. Registries may list Basic first, send several
// challenges in one header or several headers, quote commas inside scope and
// realm values and escape quotes; unknown parameters (error,
// error_description) are ignored. Errors never echo header contents.
func parseBearerChallenges(headers []string) (bearerChallenge, error) {
	sawChallenge := false
	for _, header := range headers {
		challenges, err := parseAuthChallenges(header)
		if err != nil {
			return bearerChallenge{}, err
		}
		for _, challenge := range challenges {
			sawChallenge = true
			if !strings.EqualFold(challenge.Scheme, "bearer") {
				continue
			}
			parsed := bearerChallenge{
				Realm:   challenge.Params["realm"],
				Service: challenge.Params["service"],
				Scope:   challenge.Params["scope"],
			}
			if parsed.Realm == "" {
				return bearerChallenge{}, fmt.Errorf("bearer auth challenge did not include a realm")
			}
			return parsed, nil
		}
	}
	if !sawChallenge {
		return bearerChallenge{}, fmt.Errorf("registry auth challenge is missing")
	}
	return bearerChallenge{}, fmt.Errorf("unsupported registry auth challenge")
}

// offersBasicChallenge reports whether any WWW-Authenticate header carries a
// Basic challenge. It is consulted only after no Bearer challenge was found,
// so a registry that offers both still goes through the token flow.
func offersBasicChallenge(headers []string) bool {
	for _, header := range headers {
		challenges, err := parseAuthChallenges(header)
		if err != nil {
			continue
		}
		for _, challenge := range challenges {
			if strings.EqualFold(challenge.Scheme, "basic") {
				return true
			}
		}
	}
	return false
}

// parseAuthChallenges tokenizes a WWW-Authenticate field value: a comma
// separated list of challenges, each `scheme` followed by `name=value` pairs
// (token or quoted-string with backslash escapes). A token that is not followed
// by `=` starts a new challenge.
func parseAuthChallenges(header string) ([]authChallenge, error) {
	challenges := make([]authChallenge, 0, 1)
	rest := header
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			return challenges, nil
		}
		name, after := readToken(rest)
		if name == "" {
			return nil, fmt.Errorf("malformed registry auth challenge")
		}
		after = strings.TrimLeft(after, " \t")
		if after == "" || after[0] != '=' {
			challenges = append(challenges, authChallenge{Scheme: name, Params: make(map[string]string)})
			rest = after
			continue
		}
		if len(challenges) == 0 {
			return nil, fmt.Errorf("malformed registry auth challenge")
		}
		value, remaining, err := readAuthParamValue(strings.TrimLeft(after[1:], " \t"))
		if err != nil {
			return nil, err
		}
		current := challenges[len(challenges)-1]
		key := strings.ToLower(name)
		if _, exists := current.Params[key]; !exists {
			current.Params[key] = value
		}
		rest = remaining
	}
}

// readToken consumes an RFC 7230 token (tchar+) from the input.
func readToken(input string) (string, string) {
	end := 0
	for end < len(input) && isTokenChar(input[end]) {
		end++
	}
	return input[:end], input[end:]
}

func isTokenChar(value byte) bool {
	switch {
	case value >= 'a' && value <= 'z', value >= 'A' && value <= 'Z', value >= '0' && value <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", value) >= 0
}

// readAuthParamValue consumes a token68/token or a quoted-string value.
func readAuthParamValue(input string) (string, string, error) {
	if input == "" {
		return "", "", nil
	}
	if input[0] != '"' {
		end := strings.IndexAny(input, ", \t")
		if end < 0 {
			end = len(input)
		}
		return input[:end], input[end:], nil
	}
	var value strings.Builder
	for index := 1; index < len(input); index++ {
		switch input[index] {
		case '\\':
			if index+1 >= len(input) {
				return "", "", fmt.Errorf("malformed registry auth challenge")
			}
			index++
			value.WriteByte(input[index])
		case '"':
			return value.String(), input[index+1:], nil
		default:
			value.WriteByte(input[index])
		}
	}
	return "", "", fmt.Errorf("malformed registry auth challenge")
}
