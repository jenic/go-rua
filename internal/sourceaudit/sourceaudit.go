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
	Mismatches []string
}

type Source struct {
	Key      string
	Value    string
	Location string
	resolved bool
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
	return len(r.Findings) > 0 || len(r.Incomplete) > 0 || len(r.Mismatches) > 0
}

// SourcesFromDir extracts source entries from .SRCINFO and PKGBUILD when present.
// It returns best-effort parse warnings for PKGBUILD source entries in incomplete.
func SourcesFromDir(dir string) ([]Source, []string, error) {
	srcinfoSources, pkgbuildSources, incomplete, hasSRCINFO, hasPKGBUILD, err := collectSourcesFromDir(dir)
	if err != nil {
		return nil, nil, err
	}
	if !hasSRCINFO && !hasPKGBUILD {
		return nil, nil, fmt.Errorf("no .SRCINFO or PKGBUILD found in %s", dir)
	}
	return append(append([]Source{}, srcinfoSources...), pkgbuildSources...), incomplete, nil
}

// AuditDir extracts source entries from .SRCINFO and PKGBUILD when present,
// then flags Unicode/IDN hostname spoofing risks and source metadata drift.
func AuditDir(dir string) (Report, error) {
	srcinfoSources, pkgbuildSources, incomplete, hasSRCINFO, hasPKGBUILD, err := collectSourcesFromDir(dir)
	if err != nil {
		return Report{}, err
	}
	if !hasSRCINFO && !hasPKGBUILD {
		return Report{}, fmt.Errorf("no .SRCINFO or PKGBUILD found in %s", dir)
	}

	sources := append(append([]Source{}, srcinfoSources...), pkgbuildSources...)
	report := auditSources(sources)
	report.Incomplete = append(report.Incomplete, incomplete...)
	if hasSRCINFO && hasPKGBUILD {
		report.Mismatches = append(report.Mismatches, compareSourceSets(srcinfoSources, pkgbuildSources)...)
	}
	return report, nil
}

func collectSourcesFromDir(dir string) ([]Source, []Source, []string, bool, bool, error) {
	var srcinfoSources []Source
	var pkgbuildSources []Source
	var incomplete []string
	var vars map[string]string
	hasSRCINFO := false
	hasPKGBUILD := false

	if sources, metadata, err := sourcesFromSRCINFO(filepath.Join(dir, ".SRCINFO")); err == nil {
		srcinfoSources = sources
		vars = metadata
		hasSRCINFO = true
	} else if !os.IsNotExist(err) {
		return nil, nil, nil, false, false, err
	}

	if sources, messages, err := sourcesFromPKGBUILD(filepath.Join(dir, "PKGBUILD"), vars); err == nil {
		pkgbuildSources = sources
		incomplete = messages
		hasPKGBUILD = true
	} else if !os.IsNotExist(err) {
		return nil, nil, nil, false, false, err
	}

	return srcinfoSources, pkgbuildSources, incomplete, hasSRCINFO, hasPKGBUILD, nil
}

func auditSources(sources []Source) Report {
	report := Report{Sources: sources}
	seenFindings := map[string]struct{}{}
	for _, src := range sources {
		raw := normalizeSourceURL(src.Value)
		host := sourceHost(raw)
		if host == "" {
			continue
		}
		key := raw + "\x00" + src.Location
		if _, ok := seenFindings[key]; ok {
			continue
		}
		seenFindings[key] = struct{}{}
		if finding, ok := auditHost(src, raw, host); ok {
			report.Findings = append(report.Findings, finding)
		}
	}
	return report
}

func compareSourceSets(srcinfoSources, pkgbuildSources []Source) []string {
	srcinfoByURL := sourcesByNormalizedURL(srcinfoSources)
	pkgbuildByURL := sourcesByNormalizedURL(pkgbuildSources)
	var out []string
	for raw, sources := range pkgbuildByURL {
		if _, ok := srcinfoByURL[raw]; ok {
			continue
		}
		for _, src := range sources {
			if !src.resolved {
				continue
			}
			out = append(out, fmt.Sprintf("PKGBUILD source not represented in .SRCINFO: %s %s", src.Location, src.Value))
		}
	}
	for raw, sources := range srcinfoByURL {
		if _, ok := pkgbuildByURL[raw]; ok {
			continue
		}
		if len(pkgbuildByURL) > 0 && !allSourcesResolved(pkgbuildSources) {
			continue
		}
		for _, src := range sources {
			out = append(out, fmt.Sprintf(".SRCINFO source not represented in PKGBUILD literal parsing: %s %s", src.Location, src.Value))
		}
	}
	sort.Strings(out)
	return out
}

func allSourcesResolved(sources []Source) bool {
	for _, src := range sources {
		if !src.resolved {
			return false
		}
	}
	return true
}

func sourcesByNormalizedURL(sources []Source) map[string][]Source {
	out := map[string][]Source{}
	for _, src := range sources {
		raw := normalizeSourceURL(src.Value)
		if raw == "" {
			continue
		}
		out[raw] = append(out[raw], src)
	}
	return out
}

func sourcesFromSRCINFO(path string) ([]Source, map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var out []Source
	vars := map[string]string{}
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
		value := strings.TrimSpace(parts[1])
		if isMetadataKey(key) {
			if _, ok := vars[key]; !ok {
				vars[key] = value
			}
		}
		if !isSourceKey(key) {
			continue
		}
		out = append(out, Source{
			Key:      key,
			Value:    value,
			Location: fmt.Sprintf(".SRCINFO:%d", lineNo),
			resolved: true,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return out, vars, nil
}

func sourcesFromPKGBUILD(path string, srcinfoVars map[string]string) ([]Source, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	text := string(b)
	var out []Source
	var incomplete []string
	assignments := findAssignments(text)
	for _, a := range assignments {
		if !isSourceKey(a.Key) {
			continue
		}
		line := lineNumber(text, a.Start)
		vars := varsBeforeAssignment(assignments, a.Start, srcinfoVars)
		words, complete := parseShellWords(a.Body, vars)
		if !complete {
			incomplete = append(incomplete, fmt.Sprintf("%s in PKGBUILD:%d contains shell expansion or unsupported syntax", a.Key, line))
		}
		for _, word := range words {
			out = append(out, Source{
				Key:      a.Key,
				Value:    word.Value,
				Location: fmt.Sprintf("PKGBUILD:%d", line),
				resolved: word.Complete,
			})
		}
	}
	return out, incomplete, nil
}

type assignment struct {
	Key      string
	Body     string
	Start    int
	IsArray  bool
	TopLevel bool
}

func findAssignments(text string) []assignment {
	var out []assignment
	ctx := shellScanContext{}
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
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			ctx.update(trimmed)
			i = lineEnd + 1
			continue
		}
		topLevel := ctx.topLevel()
		key, after, ok := splitAssignment(trimmed)
		if !ok {
			ctx.update(trimmed)
			i = lineEnd + 1
			continue
		}
		start := lineStart + len(line) - len(trimmed)
		body := strings.TrimSpace(after)
		isArray := false
		if strings.HasPrefix(body, "(") {
			isArray = true
			full, end := readArrayBody(text[lineStart+strings.Index(line, after):])
			body = full
			i = lineStart + strings.Index(line, after) + end
		} else {
			i = lineEnd + 1
		}
		out = append(out, assignment{Key: key, Body: body, Start: start, IsArray: isArray, TopLevel: topLevel})
	}
	return out
}

type shellScanContext struct {
	braceDepth   int
	controlDepth int
}

func (c shellScanContext) topLevel() bool {
	return c.braceDepth == 0 && c.controlDepth == 0
}

func (c *shellScanContext) update(line string) {
	braceDelta, tokens := scanShellLine(line)
	c.braceDepth += braceDelta
	if c.braceDepth < 0 {
		c.braceDepth = 0
	}
	if len(tokens) == 0 || !isControlLine(tokens[0]) {
		return
	}
	for _, token := range tokens {
		switch token {
		case "if", "for", "while", "until", "case", "select":
			c.controlDepth++
		case "fi", "done", "esac":
			if c.controlDepth > 0 {
				c.controlDepth--
			}
		}
	}
}

func isControlLine(firstToken string) bool {
	switch firstToken {
	case "if", "for", "while", "until", "case", "select", "fi", "done", "esac", "else", "elif", "then", "do":
		return true
	default:
		return false
	}
}

func scanShellLine(line string) (int, []string) {
	var tokens []string
	var token strings.Builder
	inSingle, inDouble, escaped := false, false, false
	braceDelta := 0
	flush := func() {
		if token.Len() > 0 {
			tokens = append(tokens, token.String())
			token.Reset()
		}
	}
	for _, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		switch r {
		case '#':
			if !inSingle && !inDouble {
				flush()
				return braceDelta, tokens
			}
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
		case '{':
			if !inSingle && !inDouble {
				braceDelta++
				flush()
				continue
			}
		case '}':
			if !inSingle && !inDouble {
				braceDelta--
				flush()
				continue
			}
		}
		if !inSingle && !inDouble && (unicode.IsSpace(r) || strings.ContainsRune(";()", r)) {
			flush()
			continue
		}
		if !inSingle && !inDouble {
			token.WriteRune(r)
		}
	}
	flush()
	return braceDelta, tokens
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

type shellWord struct {
	Value    string
	Complete bool
}

func parseShellWords(s string, vars map[string]string) ([]shellWord, bool) {
	var words []shellWord
	var b strings.Builder
	inSingle, inDouble, escaped := false, false, false
	complete := true
	wordComplete := true
	flush := func() {
		if b.Len() > 0 {
			words = append(words, shellWord{Value: b.String(), Complete: wordComplete})
			b.Reset()
			wordComplete = true
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if escaped {
			b.WriteRune(r)
			escaped = false
			i += size
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			i += size
			continue
		}
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
				i += size
				continue
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
				i += size
				continue
			}
		case '$':
			if !inSingle {
				value, raw, consumed, ok := expandShellVariable(s, i, vars)
				if ok {
					b.WriteString(value)
				} else {
					b.WriteString(raw)
					complete = false
					wordComplete = false
				}
				i += consumed
				continue
			}
		case '`':
			if !inSingle {
				complete = false
				wordComplete = false
			}
		}
		if unicode.IsSpace(r) && !inSingle && !inDouble {
			flush()
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	if inSingle || inDouble || escaped {
		complete = false
		wordComplete = false
	}
	flush()
	return words, complete
}

func varsBeforeAssignment(assignments []assignment, start int, srcinfoVars map[string]string) map[string]string {
	vars := map[string]string{}
	for key, value := range srcinfoVars {
		vars[key] = value
	}
	for _, a := range assignments {
		if a.Start >= start {
			break
		}
		if !a.TopLevel || isSourceKey(a.Key) || !isVariableKey(a.Key) {
			continue
		}
		words, complete := parseShellWords(a.Body, vars)
		if !complete || len(words) == 0 {
			continue
		}
		if !a.IsArray && len(words) != 1 {
			continue
		}
		vars[a.Key] = words[0].Value
	}
	return vars
}

func expandShellVariable(s string, start int, vars map[string]string) (string, string, int, bool) {
	if start+1 >= len(s) {
		return "$", "$", 1, false
	}
	next := s[start+1]
	if next == '{' {
		end := strings.IndexByte(s[start+2:], '}')
		if end < 0 {
			return "$", "$", 1, false
		}
		end += start + 2
		raw := s[start : end+1]
		value, ok := resolveBracedVariable(raw[2:len(raw)-1], vars)
		return value, raw, len(raw), ok
	}
	if !isVariableStart(next) {
		return "$", "$", 1, false
	}
	end := start + 2
	for end < len(s) && isVariablePart(s[end]) {
		end++
	}
	name := s[start+1 : end]
	value, ok := vars[name]
	return value, s[start:end], end - start, ok
}

func resolveBracedVariable(body string, vars map[string]string) (string, bool) {
	if isVariableKey(body) {
		value, ok := vars[body]
		return value, ok
	}
	name, op, pattern, ok := splitTrimExpansion(body)
	if !ok || !isVariableKey(name) || !isLiteralTrimPattern(pattern) {
		return "", false
	}
	value, ok := vars[name]
	if !ok {
		return "", false
	}
	switch op {
	case "%", "%%":
		return strings.TrimSuffix(value, pattern), true
	case "#", "##":
		return strings.TrimPrefix(value, pattern), true
	default:
		return "", false
	}
}

func splitTrimExpansion(body string) (string, string, string, bool) {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '%', '#':
			op := body[i : i+1]
			patternStart := i + 1
			if patternStart < len(body) && body[patternStart] == body[i] {
				op = body[i : i+2]
				patternStart++
			}
			return body[:i], op, body[patternStart:], true
		case ':', '/', '!', '=', '?', '+', '-', '[':
			return "", "", "", false
		}
	}
	return "", "", "", false
}

func isSourceKey(key string) bool {
	return key == "source" || strings.HasPrefix(key, "source_")
}

func isMetadataKey(key string) bool {
	switch key {
	case "pkgbase", "pkgname", "pkgver", "pkgrel", "epoch":
		return true
	default:
		return false
	}
}

func isVariableKey(key string) bool {
	if key == "" || !isVariableStart(key[0]) {
		return false
	}
	for i := 1; i < len(key); i++ {
		if !isVariablePart(key[i]) {
			return false
		}
	}
	return true
}

func isVariableStart(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

func isVariablePart(b byte) bool {
	return isVariableStart(b) || ('0' <= b && b <= '9')
}

func isLiteralTrimPattern(pattern string) bool {
	for _, r := range pattern {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
		switch r {
		case '$', '`', '\'', '"', '\\', '*', '?', '[', ']':
			return false
		}
	}
	return true
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
