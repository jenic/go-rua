package sourceaudit

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/runenames"
)

// Report describes source URL spoofing risks found in package source metadata.
type Report struct {
	Sources    []Source
	Findings   []Finding
	Incomplete []string
}

type Source struct {
	Key      string
	Value    string
	Location string
}

type Finding struct {
	Source      Source
	URL         string
	Host        string
	ASCIIHost   string
	UnicodeHost string
	Reasons     []string
	Codepoints  []string
}

func (r Report) HasWarnings() bool {
	return len(r.Findings) > 0 || len(r.Incomplete) > 0
}

// AuditDir extracts source entries from .SRCINFO, or from PKGBUILD as a
// best-effort fallback, and flags Unicode/IDN hostname spoofing risks.
func AuditDir(dir string) (Report, error) {
	if sources, err := sourcesFromSRCINFO(filepath.Join(dir, ".SRCINFO")); err == nil {
		return auditSources(sources), nil
	} else if !os.IsNotExist(err) {
		return Report{}, err
	}
	sources, incomplete, err := sourcesFromPKGBUILD(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return Report{}, err
	}
	report := auditSources(sources)
	report.Incomplete = append(report.Incomplete, incomplete...)
	return report, nil
}

func auditSources(sources []Source) Report {
	report := Report{Sources: sources}
	for _, src := range sources {
		raw := normalizeSourceURL(src.Value)
		host := sourceHost(raw)
		if host == "" {
			continue
		}
		if finding, ok := auditHost(src, raw, host); ok {
			report.Findings = append(report.Findings, finding)
		}
	}
	return report
}

func sourcesFromSRCINFO(path string) ([]Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Source
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !isSourceKey(key) {
			continue
		}
		out = append(out, Source{
			Key:      key,
			Value:    strings.TrimSpace(parts[1]),
			Location: fmt.Sprintf(".SRCINFO:%d", lineNo),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func sourcesFromPKGBUILD(path string) ([]Source, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	text := string(b)
	var out []Source
	var incomplete []string
	for _, a := range findAssignments(text) {
		words, complete := parseShellWords(a.Body)
		if !complete {
			incomplete = append(incomplete, fmt.Sprintf("%s in PKGBUILD:%d contains shell expansion or unsupported syntax", a.Key, lineNumber(text, a.Start)))
		}
		for _, word := range words {
			out = append(out, Source{
				Key:      a.Key,
				Value:    word,
				Location: fmt.Sprintf("PKGBUILD:%d", lineNumber(text, a.Start)),
			})
		}
	}
	return out, incomplete, nil
}

type assignment struct {
	Key   string
	Body  string
	Start int
}

func findAssignments(text string) []assignment {
	var out []assignment
	for i := 0; i < len(text); {
		lineStart := i
		lineEnd := strings.IndexByte(text[i:], '\n')
		if lineEnd < 0 {
			lineEnd = len(text)
		} else {
			lineEnd += i
		}
		line := text[lineStart:lineEnd]
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			i = lineEnd + 1
			continue
		}
		key, after, ok := splitAssignment(trimmed)
		if !ok || !isSourceKey(key) {
			i = lineEnd + 1
			continue
		}
		start := lineStart + len(line) - len(trimmed)
		body := strings.TrimSpace(after)
		if strings.HasPrefix(body, "(") {
			full, end := readArrayBody(text[lineStart+strings.Index(line, after):])
			body = full
			i = lineStart + strings.Index(line, after) + end
		} else {
			i = lineEnd + 1
		}
		out = append(out, assignment{Key: key, Body: body, Start: start})
	}
	return out
}

func splitAssignment(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, line[eq+1:], true
}

func readArrayBody(s string) (string, int) {
	inSingle, inDouble, escaped := false, false, false
	depth := 0
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble {
				depth--
				if depth == 0 {
					return s[1:i], i + 1
				}
			}
		}
	}
	return strings.TrimPrefix(s, "("), len(s)
}

func parseShellWords(s string) ([]string, bool) {
	var words []string
	var b strings.Builder
	inSingle, inDouble, escaped := false, false, false
	complete := true
	flush := func() {
		if b.Len() > 0 {
			words = append(words, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
				continue
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
				continue
			}
		case '$', '`':
			if !inSingle {
				complete = false
			}
		}
		if unicode.IsSpace(r) && !inSingle && !inDouble {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	if inSingle || inDouble || escaped {
		complete = false
	}
	return words, complete
}

func isSourceKey(key string) bool {
	return key == "source" || strings.HasPrefix(key, "source_")
}

func normalizeSourceURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "::"); i >= 0 {
		raw = raw[i+2:]
	}
	if i := strings.Index(raw, "://"); i > 0 {
		scheme := raw[:i]
		if j := strings.LastIndexByte(scheme, '+'); j >= 0 {
			raw = scheme[j+1:] + raw[i:]
		}
	}
	return raw
}

func sourceHost(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if host := scpLikeHost(raw); host != "" {
		return host
	}
	return ""
}

func scpLikeHost(raw string) string {
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, " \t\n") {
		return ""
	}
	colon := strings.IndexByte(raw, ':')
	if colon <= 0 {
		return ""
	}
	left := raw[:colon]
	if slash := strings.IndexByte(left, '/'); slash >= 0 {
		return ""
	}
	if at := strings.LastIndexByte(left, '@'); at >= 0 {
		left = left[at+1:]
	}
	if net.ParseIP(left) != nil || strings.Contains(left, ".") {
		return left
	}
	return ""
}

func auditHost(src Source, rawURL, host string) (Finding, bool) {
	reasons := []string{}
	codepoints := []string{}
	asciiHost, err := idna.Lookup.ToASCII(host)
	if err != nil {
		reasons = append(reasons, "hostname is not valid IDNA")
	}
	if asciiHost != "" && !strings.EqualFold(asciiHost, host) {
		reasons = append(reasons, "IDNA/Punycode form differs from displayed hostname")
	}
	unicodeHost, unicodeErr := idna.Lookup.ToUnicode(host)
	if unicodeErr == nil && !strings.EqualFold(unicodeHost, host) {
		reasons = append(reasons, "hostname contains Punycode/IDN label")
		for _, r := range unicodeHost {
			if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
				codepoints = append(codepoints, describeRune(r))
			}
		}
	}
	if !isASCII(host) {
		reasons = append(reasons, "hostname contains non-ASCII Unicode characters")
	}
	if !norm.NFC.IsNormalString(host) {
		reasons = append(reasons, "hostname is not NFC normalized")
	}
	for _, r := range host {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			codepoints = append(codepoints, describeRune(r))
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			reasons = append(reasons, "hostname contains control or default-ignorable characters")
		}
	}
	for _, label := range strings.Split(host, ".") {
		if mixedScripts(label) {
			reasons = append(reasons, "hostname label mixes Unicode scripts")
			break
		}
	}
	reasons = uniqueStrings(reasons)
	if len(reasons) == 0 {
		return Finding{}, false
	}
	return Finding{
		Source:      src,
		URL:         rawURL,
		Host:        host,
		ASCIIHost:   asciiHost,
		UnicodeHost: unicodeHost,
		Reasons:     reasons,
		Codepoints:  codepoints,
	}, true
}

func mixedScripts(label string) bool {
	scripts := map[string]struct{}{}
	for _, r := range label {
		script := scriptName(r)
		if script == "" {
			continue
		}
		scripts[script] = struct{}{}
	}
	return len(scripts) > 1
}

func scriptName(r rune) string {
	switch {
	case unicode.In(r, unicode.Latin):
		return "Latin"
	case unicode.In(r, unicode.Cyrillic):
		return "Cyrillic"
	case unicode.In(r, unicode.Greek):
		return "Greek"
	case unicode.In(r, unicode.Han):
		return "Han"
	case unicode.In(r, unicode.Hiragana):
		return "Hiragana"
	case unicode.In(r, unicode.Katakana):
		return "Katakana"
	case unicode.In(r, unicode.Hangul):
		return "Hangul"
	case unicode.In(r, unicode.Hebrew):
		return "Hebrew"
	case unicode.In(r, unicode.Arabic):
		return "Arabic"
	case unicode.In(r, unicode.Devanagari):
		return "Devanagari"
	case unicode.In(r, unicode.Thai):
		return "Thai"
	default:
		return ""
	}
}

func describeRune(r rune) string {
	name := runenames.Name(r)
	if name == "" {
		name = "UNKNOWN"
	}
	return fmt.Sprintf("U+%04X %q %s", r, r, name)
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return utf8.ValidString(s)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func lineNumber(text string, offset int) int {
	if offset < 0 {
		return 1
	}
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}
