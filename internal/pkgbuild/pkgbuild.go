// Package pkgbuild provides conservative structured PKGBUILD inspection and
// rewriting without evaluating shell code.
package pkgbuild

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

type Assignment struct {
	Key    string
	Values []string
	Start  uint
	End    uint
	Array  bool
}

type Metadata struct {
	PackageBase   string
	PackageName   string
	Version       string
	Release       string
	Epoch         string
	Architectures []string
	Assignments   map[string]Assignment
	Sources       map[string][]string
	Checksums     map[string][]string
	ValidPGPKeys  []string
}

type Override struct {
	Version   string
	Release   string
	Sources   map[string][]string
	Checksums map[string][]string
}

func Parse(src []byte) (Metadata, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_bash.Language())); err != nil {
		return Metadata{}, err
	}
	tree := parser.Parse(src, nil)
	if tree == nil {
		return Metadata{}, fmt.Errorf("tree-sitter parse returned no tree")
	}
	defer tree.Close()
	root := tree.RootNode()
	if root.HasError() {
		return Metadata{}, fmt.Errorf("PKGBUILD contains shell syntax errors")
	}

	meta := Metadata{Assignments: map[string]Assignment{}, Sources: map[string][]string{}, Checksums: map[string][]string{}}
	var parseErr error
	walk(root, func(node *tree_sitter.Node) {
		if parseErr != nil || node.Kind() != "variable_assignment" {
			return
		}
		text := strings.TrimSpace(node.Utf8Text(src))
		key, rhs, appendMode, ok := splitAssignment(text)
		if !ok || !relevantKey(key) {
			return
		}
		parent := node.Parent()
		if parent == nil || parent.Id() != root.Id() {
			parseErr = fmt.Errorf("%s is not a top-level assignment", key)
			return
		}
		if appendMode {
			parseErr = fmt.Errorf("%s+= is unsupported", key)
			return
		}
		if _, exists := meta.Assignments[key]; exists {
			parseErr = fmt.Errorf("duplicate %s assignment", key)
			return
		}
		assignment := Assignment{Key: key, Start: node.StartByte(), End: node.EndByte()}
		if strings.HasPrefix(strings.TrimSpace(rhs), "(") {
			assignment.Array = true
			values, err := parseLiteralArray(rhs)
			if err != nil {
				parseErr = fmt.Errorf("%s: %w", key, err)
				return
			}
			assignment.Values = values
		} else {
			value, err := parseLiteralScalar(rhs)
			if err != nil {
				parseErr = fmt.Errorf("%s: %w", key, err)
				return
			}
			assignment.Values = []string{value}
		}
		meta.Assignments[key] = assignment
	})
	if parseErr != nil {
		return Metadata{}, parseErr
	}

	for _, key := range []string{"pkgbase", "pkgname", "pkgver", "pkgrel", "epoch"} {
		assignment, ok := meta.Assignments[key]
		if !ok {
			continue
		}
		if assignment.Array && key != "pkgname" || len(assignment.Values) != 1 {
			return Metadata{}, fmt.Errorf("%s must be one literal value", key)
		}
		value := assignment.Values[0]
		switch key {
		case "pkgbase":
			meta.PackageBase = value
		case "pkgname":
			meta.PackageName = value
		case "pkgver":
			meta.Version = value
		case "pkgrel":
			meta.Release = value
		case "epoch":
			meta.Epoch = value
		}
	}
	if assignment, ok := meta.Assignments["arch"]; ok {
		if !assignment.Array || len(assignment.Values) == 0 {
			return Metadata{}, fmt.Errorf("arch must be a non-empty literal array")
		}
		meta.Architectures = append([]string(nil), assignment.Values...)
	}
	if meta.PackageBase == "" {
		meta.PackageBase = meta.PackageName
	}
	if meta.PackageBase == "" || meta.Version == "" || meta.Release == "" {
		return Metadata{}, fmt.Errorf("PKGBUILD requires literal pkgbase/pkgname, pkgver, and pkgrel")
	}
	vars := map[string]string{"pkgbase": meta.PackageBase, "pkgname": meta.PackageName, "pkgver": meta.Version, "pkgrel": meta.Release, "epoch": meta.Epoch}
	for key, assignment := range meta.Assignments {
		switch {
		case key == "source" || strings.HasPrefix(key, "source_"):
			if !assignment.Array {
				return Metadata{}, fmt.Errorf("%s must be a literal array", key)
			}
			values := make([]string, len(assignment.Values))
			for i, value := range assignment.Values {
				resolved, err := expandPrimitive(value, vars)
				if err != nil {
					return Metadata{}, fmt.Errorf("%s[%d]: %w", key, i, err)
				}
				values[i] = resolved
			}
			meta.Sources[key] = values
		case isChecksumKey(key):
			if !assignment.Array {
				return Metadata{}, fmt.Errorf("%s must be a literal array", key)
			}
			for _, value := range assignment.Values {
				if strings.ContainsAny(value, "$`()") {
					return Metadata{}, fmt.Errorf("%s contains dynamic value", key)
				}
			}
			meta.Checksums[key] = append([]string(nil), assignment.Values...)
		case key == "validpgpkeys":
			if !assignment.Array {
				return Metadata{}, fmt.Errorf("validpgpkeys must be a literal array")
			}
			for _, value := range assignment.Values {
				value = strings.ToUpper(strings.TrimSpace(value))
				if !validFingerprint(value) {
					return Metadata{}, fmt.Errorf("invalid validpgpkeys fingerprint %q", value)
				}
				meta.ValidPGPKeys = append(meta.ValidPGPKeys, value)
			}
		}
	}
	return meta, nil
}

func Rewrite(src []byte, override Override) ([]byte, error) {
	meta, err := Parse(src)
	if err != nil {
		return nil, err
	}
	if override.Version == "" {
		return nil, fmt.Errorf("override version is empty")
	}
	if override.Release == "" {
		override.Release = "1"
	}
	replacements := map[string][]string{"pkgver": {override.Version}, "pkgrel": {override.Release}}
	for key, values := range override.Sources {
		replacements[key] = values
	}
	for key, values := range override.Checksums {
		replacements[key] = values
	}
	type edit struct {
		start, end uint
		text       string
	}
	var edits []edit
	for key, values := range replacements {
		assignment, ok := meta.Assignments[key]
		if !ok {
			return nil, fmt.Errorf("cannot rewrite missing %s assignment", key)
		}
		if assignment.Array && len(values) != len(assignment.Values) {
			return nil, fmt.Errorf("%s index mapping changed", key)
		}
		text := key + "=" + quote(values[0])
		if assignment.Array {
			text = key + "=(" + joinQuoted(values) + ")"
		}
		edits = append(edits, edit{assignment.Start, assignment.End, text})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), src...)
	for _, edit := range edits {
		next := make([]byte, 0, len(out)-int(edit.end-edit.start)+len(edit.text))
		next = append(next, out[:edit.start]...)
		next = append(next, edit.text...)
		next = append(next, out[edit.end:]...)
		out = next
	}
	check, err := Parse(out)
	if err != nil {
		return nil, fmt.Errorf("validate rewritten PKGBUILD: %w", err)
	}
	if check.Version != override.Version || check.Release != override.Release || check.Epoch != meta.Epoch {
		return nil, fmt.Errorf("rewritten version fields do not match override")
	}
	for key, values := range override.Sources {
		if !equal(check.Sources[key], values) {
			return nil, fmt.Errorf("rewritten %s differs", key)
		}
	}
	for key, values := range override.Checksums {
		if !equal(check.Checksums[key], values) {
			return nil, fmt.Errorf("rewritten %s differs", key)
		}
	}
	if check.PackageBase != meta.PackageBase || check.PackageName != meta.PackageName || check.Epoch != meta.Epoch || !equal(check.Architectures, meta.Architectures) || !equal(check.ValidPGPKeys, meta.ValidPGPKeys) {
		return nil, fmt.Errorf("rewrite changed unrelated package metadata")
	}
	for key, before := range meta.Sources {
		want := before
		if values, ok := override.Sources[key]; ok {
			want = values
		}
		if !equal(check.Sources[key], want) {
			return nil, fmt.Errorf("rewrite changed unrelated %s values", key)
		}
	}
	for key, before := range meta.Checksums {
		want := before
		if values, ok := override.Checksums[key]; ok {
			want = values
		}
		if !equal(check.Checksums[key], want) {
			return nil, fmt.Errorf("rewrite changed unrelated %s values", key)
		}
	}
	return out, nil
}

func splitAssignment(text string) (key, rhs string, appendMode, ok bool) {
	index := strings.IndexByte(text, '=')
	if index <= 0 {
		return "", "", false, false
	}
	key = strings.TrimSpace(text[:index])
	if strings.HasSuffix(key, "+") {
		appendMode, key = true, strings.TrimSuffix(key, "+")
	}
	if key == "" {
		return "", "", false, false
	}
	return key, strings.TrimSpace(text[index+1:]), appendMode, true
}

func relevantKey(key string) bool {
	return key == "pkgbase" || key == "pkgname" || key == "pkgver" || key == "pkgrel" || key == "epoch" || key == "arch" || key == "validpgpkeys" || key == "source" || strings.HasPrefix(key, "source_") || isChecksumKey(key)
}

func isChecksumKey(key string) bool {
	for _, prefix := range []string{"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"} {
		if key == prefix || strings.HasPrefix(key, prefix+"_") {
			return true
		}
	}
	return false
}

func parseLiteralScalar(rhs string) (string, error) {
	values, err := parseWords(rhs)
	if err != nil || len(values) != 1 {
		return "", fmt.Errorf("expected one literal value")
	}
	return values[0], nil
}
func parseLiteralArray(rhs string) ([]string, error) {
	rhs = strings.TrimSpace(rhs)
	if len(rhs) < 2 || rhs[0] != '(' || rhs[len(rhs)-1] != ')' {
		return nil, fmt.Errorf("expected literal array")
	}
	return parseWords(rhs[1 : len(rhs)-1])
}
func parseWords(input string) ([]string, error) {
	var values []string
	var b strings.Builder
	quoteChar := byte(0)
	escaped := false
	inWord := false
	flush := func() {
		if inWord {
			values = append(values, b.String())
			b.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '`' {
			return nil, fmt.Errorf("command substitution is unsupported")
		}
		if escaped {
			if c == '\n' {
				escaped = false
				continue
			}
			if c == '$' {
				return nil, fmt.Errorf("escaped shell expansions are unsupported")
			}
			b.WriteByte(c)
			inWord = true
			escaped = false
			continue
		}
		if c == '\\' && quoteChar != '\'' {
			if quoteChar == '"' && i+1 < len(input) && !strings.ContainsRune("$`\"\\\n", rune(input[i+1])) {
				b.WriteByte(c)
			} else {
				escaped = true
			}
			continue
		}
		if quoteChar != 0 {
			if c == quoteChar {
				quoteChar = 0
			} else {
				if quoteChar == '\'' && c == '$' {
					return nil, fmt.Errorf("single-quoted shell expansions are unsupported")
				}
				b.WriteByte(c)
				inWord = true
			}
			continue
		}
		if c == '\'' || c == '"' {
			quoteChar = c
			inWord = true
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		if c == '#' {
			return nil, fmt.Errorf("comments in literal assignments are unsupported")
		}
		if strings.ContainsRune(";()`|&<>", rune(c)) {
			return nil, fmt.Errorf("dynamic shell syntax is unsupported")
		}
		unclosedParameter := strings.LastIndex(b.String(), "${") > strings.LastIndex(b.String(), "}")
		if strings.ContainsRune("*?[", rune(c)) || c == ']' || c == '~' && !inWord || c == '{' && (i == 0 || input[i-1] != '$') || c == '}' && !unclosedParameter {
			return nil, fmt.Errorf("unquoted glob, brace, or tilde expansion is unsupported")
		}
		b.WriteByte(c)
		inWord = true
	}
	if quoteChar != 0 || escaped {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	flush()
	return values, nil
}
func expandPrimitive(value string, vars map[string]string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '$' {
			out.WriteByte(value[i])
			i++
			continue
		}
		if i+1 < len(value) && value[i+1] == '{' {
			end := strings.IndexByte(value[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("unsupported shell expansion")
			}
			end += i + 2
			name := value[i+2 : end]
			replacement, ok := vars[name]
			if name == "pkgname%-bin" {
				replacement, ok = strings.TrimSuffix(vars["pkgname"], "-bin"), vars["pkgname"] != ""
			}
			if !ok {
				return "", fmt.Errorf("unsupported shell expansion %q", name)
			}
			out.WriteString(replacement)
			i = end + 1
			continue
		}
		end := i + 1
		for end < len(value) && (value[end] >= 'a' && value[end] <= 'z' || value[end] >= 'A' && value[end] <= 'Z' || value[end] >= '0' && value[end] <= '9' || value[end] == '_') {
			end++
		}
		name := value[i+1 : end]
		replacement, ok := vars[name]
		if !ok || name == "" {
			return "", fmt.Errorf("unsupported shell expansion %q", name)
		}
		out.WriteString(replacement)
		i = end
	}
	return out.String(), nil
}

// SourcesAt resolves the already-validated primitive source templates using
// replacement pkgver and pkgrel values. No additional shell syntax is evaluated.
func (m Metadata) SourcesAt(version, release string) (map[string][]string, error) {
	if version == "" || release == "" {
		return nil, fmt.Errorf("source version or release is empty")
	}
	vars := map[string]string{"pkgbase": m.PackageBase, "pkgname": m.PackageName, "pkgver": version, "pkgrel": release, "epoch": m.Epoch}
	resolved := make(map[string][]string, len(m.Sources))
	for key := range m.Sources {
		assignment := m.Assignments[key]
		values := make([]string, len(assignment.Values))
		for i, value := range assignment.Values {
			expanded, err := expandPrimitive(value, vars)
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", key, i, err)
			}
			values[i] = expanded
		}
		resolved[key] = values
	}
	return resolved, nil
}
func validFingerprint(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func joinQuoted(values []string) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = quote(v)
	}
	return strings.Join(parts, " ")
}
func equal(a, b []string) bool {
	return bytes.Equal([]byte(strings.Join(a, "\x00")), []byte(strings.Join(b, "\x00")))
}
func walk(node *tree_sitter.Node, visit func(*tree_sitter.Node)) {
	visit(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		walk(node.NamedChild(i), visit)
	}
}
