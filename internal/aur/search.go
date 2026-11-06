package aur

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type searchTerm struct {
	literal string // Longest required substring, suitable for the RPC query.
	pattern *regexp.Regexp
}

func parseSearchTerm(term string) (searchTerm, error) {
	if term == "" {
		return searchTerm{}, fmt.Errorf("search terms must not be empty")
	}
	text := strings.ToLower(term)
	prefix, suffix := strings.HasPrefix(text, "^"), strings.HasSuffix(text, "$")
	if prefix {
		text = strings.TrimPrefix(text, "^")
	}
	if suffix {
		text = strings.TrimSuffix(text, "$")
	}
	wildcard := strings.Contains(text, "*")
	if !prefix && !suffix && !wildcard {
		return searchTerm{literal: text}, nil
	}

	// Only * and the outer anchors have special meaning. Quote everything else
	// so package-name punctuation such as '.' and '+' remains literal.
	parts := strings.Split(text, "*")
	var literal string
	for i, part := range parts {
		if utf8.RuneCountInString(part) > utf8.RuneCountInString(literal) {
			literal = part
		}
		parts[i] = regexp.QuoteMeta(part)
	}
	expression := strings.Join(parts, ".*")
	if prefix || wildcard {
		expression = "^" + expression
	}
	if suffix || wildcard {
		expression += "$"
	}
	pattern, err := regexp.Compile(expression)
	if err != nil {
		return searchTerm{}, fmt.Errorf("invalid search pattern %q: %w", term, err)
	}
	return searchTerm{literal: literal, pattern: pattern}, nil
}

func (t searchTerm) matches(name, description string) bool {
	if t.pattern != nil {
		return t.pattern.MatchString(name)
	}
	return strings.Contains(name, t.literal) || strings.Contains(description, t.literal)
}
