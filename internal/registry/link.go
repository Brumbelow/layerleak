package registry

import (
	"fmt"
	"net/url"
	"strings"
)

// webLink is one link-value of an RFC 8288 Link header field.
type webLink struct {
	Target string
	Params map[string]string
}

// nextLinkURL resolves the rel="next" target of the Link response headers
// against the current pagination URL. It returns ok=false with a nil error when
// the headers carry no next relation (the last page) and an error when a header
// cannot be parsed, so callers never treat an unreadable continuation as the end
// of the listing. Error messages never echo header contents.
func nextLinkURL(currentURL string, headers []string) (string, bool, error) {
	target := ""
	for _, header := range headers {
		links, err := parseLinkHeader(header)
		if err != nil {
			return "", false, err
		}
		for _, link := range links {
			if !link.hasRelation("next") {
				continue
			}
			if target != "" {
				return "", false, fmt.Errorf("parse link header: multiple next relations")
			}
			target = link.Target
		}
	}
	if target == "" {
		return "", false, nil
	}

	parsedCurrent, err := url.Parse(currentURL)
	if err != nil {
		return "", false, fmt.Errorf("current pagination url is invalid")
	}
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return "", false, fmt.Errorf("pagination link url is invalid")
	}
	return parsedCurrent.ResolveReference(parsedTarget).String(), true, nil
}

func (l webLink) hasRelation(relation string) bool {
	for _, value := range strings.Fields(l.Params["rel"]) {
		if strings.EqualFold(value, relation) {
			return true
		}
	}
	return false
}

// parseLinkHeader tokenizes one Link header field value per RFC 8288 section 3:
// a comma-separated list of `<URI-Reference>` targets, each followed by
// `; name=value` parameters whose values are tokens or quoted strings.
func parseLinkHeader(header string) ([]webLink, error) {
	links := make([]webLink, 0, 1)
	rest := header
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			return links, nil
		}
		link, remaining, err := readLinkTarget(rest)
		if err != nil {
			return nil, err
		}
		rest, err = readLinkParams(link.Params, remaining)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
}

// readLinkTarget consumes the `<URI-Reference>` that starts a link-value and
// returns the link with an empty parameter map and the remaining input.
func readLinkTarget(rest string) (webLink, string, error) {
	if rest[0] != '<' {
		return webLink{}, "", fmt.Errorf("parse link header: missing link target")
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return webLink{}, "", fmt.Errorf("parse link header: unterminated link target")
	}
	link := webLink{Target: strings.TrimSpace(rest[1:end]), Params: make(map[string]string)}
	if link.Target == "" {
		return webLink{}, "", fmt.Errorf("parse link header: missing url")
	}
	return link, rest[end+1:], nil
}

// readLinkParams consumes the `; name=value` parameters of one link-value up
// to the next comma or the end of the input. The first occurrence of a
// parameter name wins.
func readLinkParams(params map[string]string, rest string) (string, error) {
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" || rest[0] == ',' {
			return rest, nil
		}
		if rest[0] != ';' {
			return "", fmt.Errorf("parse link header: unexpected character after link target")
		}
		name, value, remaining, err := readLinkParam(strings.TrimLeft(rest[1:], " \t"))
		if err != nil {
			return "", err
		}
		rest = remaining
		if _, exists := params[name]; !exists {
			params[name] = value
		}
	}
}

// readLinkParam consumes one parameter after its `;`: a lower-cased name and,
// when an `=` follows, its token or quoted-string value.
func readLinkParam(rest string) (string, string, string, error) {
	nameEnd := strings.IndexAny(rest, "=;, \t")
	if nameEnd < 0 {
		nameEnd = len(rest)
	}
	name := strings.ToLower(rest[:nameEnd])
	if name == "" {
		return "", "", "", fmt.Errorf("parse link header: missing parameter name")
	}
	rest = strings.TrimLeft(rest[nameEnd:], " \t")
	value := ""
	if rest != "" && rest[0] == '=' {
		var err error
		value, rest, err = readParamValue(strings.TrimLeft(rest[1:], " \t"))
		if err != nil {
			return "", "", "", err
		}
	}
	return name, value, rest, nil
}

// readParamValue consumes a token or quoted-string (with backslash escapes)
// and returns the decoded value and the remaining input.
func readParamValue(input string) (string, string, error) {
	if input == "" {
		return "", "", nil
	}
	if input[0] != '"' {
		end := strings.IndexAny(input, ";, \t")
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
				return "", "", fmt.Errorf("parse link header: unterminated quoted value")
			}
			index++
			value.WriteByte(input[index])
		case '"':
			return value.String(), input[index+1:], nil
		default:
			value.WriteByte(input[index])
		}
	}
	return "", "", fmt.Errorf("parse link header: unterminated quoted value")
}
