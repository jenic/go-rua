package shellaudit

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

const maxEvidenceLen = 160

var base64BlobRE = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)

// Report describes suspicious shell logic found in package scripts.
type Report struct {
	Files      []FileReport
	Findings   []Finding
	Incomplete []string
}

type FileReport struct {
	Path string
}

type Finding struct {
	File     string
	Line     int
	Column   int
	Rule     string
	Severity string
	Evidence string
	Reason   string
}

func (r Report) HasWarnings() bool {
	return len(r.Findings) > 0 || len(r.Incomplete) > 0
}

// AuditDir parses PKGBUILD and any static install hook referenced by it.
func AuditDir(dir string) (Report, error) {
	pkgbuild := filepath.Join(dir, "PKGBUILD")
	if _, err := os.Stat(pkgbuild); err != nil {
		return Report{}, fmt.Errorf("PKGBUILD not found in %s: %w", dir, err)
	}
	report := Report{}
	if err := auditFile(&report, dir, pkgbuild); err != nil {
		return Report{}, err
	}
	hooks, incomplete, err := installHooks(dir, pkgbuild)
	if err != nil {
		return Report{}, err
	}
	report.Incomplete = append(report.Incomplete, incomplete...)
	for _, hook := range hooks {
		if err := auditFile(&report, dir, hook); err != nil {
			report.Incomplete = append(report.Incomplete, fmt.Sprintf("%s could not be audited: %v", relPath(dir, hook), err))
		}
	}
	sortReport(&report)
	return report, nil
}

func auditFile(report *Report, root, path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rel := relPath(root, path)
	report.Files = append(report.Files, FileReport{Path: rel})

	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_bash.Language())); err != nil {
		return err
	}
	tree := parser.Parse(src, nil)
	if tree == nil {
		return fmt.Errorf("tree-sitter parse returned no tree")
	}
	defer tree.Close()
	rootNode := tree.RootNode()
	if rootNode.HasError() {
		report.Incomplete = append(report.Incomplete, fmt.Sprintf("%s contains shell syntax tree errors; audit may be incomplete", rel))
	}
	seen := map[string]struct{}{}
	walk(rootNode, func(n *tree_sitter.Node) {
		auditNode(report, seen, rel, src, n)
	})
	return nil
}

func auditNode(report *Report, seen map[string]struct{}, file string, src []byte, n *tree_sitter.Node) {
	kind := n.Kind()
	text := n.Utf8Text(src)
	switch kind {
	case "command":
		tokens := normalizeCommandTokens(shellWords(text))
		auditCommand(report, seen, file, src, n, tokens, text)
	case "pipeline":
		auditPipeline(report, seen, file, src, n)
	case "word", "string", "raw_string", "heredoc_body", "heredoc_content":
		auditTextPayloads(report, seen, file, src, n, text)
	}
}

func auditCommand(report *Report, seen map[string]struct{}, file string, src []byte, n *tree_sitter.Node, tokens []string, text string) {
	if len(tokens) == 0 {
		return
	}
	cmd := commandBase(tokens[0])
	switch {
	case cmd == "eval":
		addFinding(report, seen, file, n, "eval", "high", text, "eval executes shell code assembled at runtime")
	case isShell(cmd) && hasFlag(tokens[1:], "-c"):
		addFinding(report, seen, file, n, "shell-c", "high", text, "shell interpreter is invoked with -c")
	case isThirdPartyInstall(tokens):
		addFinding(report, seen, file, n, "third-party-install", "medium", text, "package script invokes a third-party module installer")
	}
	auditTextPayloads(report, seen, file, src, n, text)
}

func auditPipeline(report *Report, seen map[string]struct{}, file string, src []byte, n *tree_sitter.Node) {
	var commands [][]string
	collectCommands(n, src, &commands)
	for i := 0; i+1 < len(commands); i++ {
		left := commands[i]
		right := commands[i+1]
		if len(left) == 0 || len(right) == 0 {
			continue
		}
		if isDownloader(commandBase(left[0])) && isShell(commandBase(right[0])) {
			addFinding(report, seen, file, n, "download-pipe-shell", "high", n.Utf8Text(src), "downloaded content is piped into a shell interpreter")
			return
		}
	}
}

func auditTextPayloads(report *Report, seen map[string]struct{}, file string, src []byte, n *tree_sitter.Node, text string) {
	if strings.Contains(text, "/dev/tcp/") || strings.Contains(text, "/dev/udp/") {
		addFinding(report, seen, file, n, "dev-tcp", "high", text, "script references bash network pseudo-devices")
	}
	if containsBase64Blob(text) {
		addFinding(report, seen, file, n, "embedded-base64", "medium", text, "script contains a long base64-decodable blob")
	}
}

func collectCommands(n *tree_sitter.Node, src []byte, out *[][]string) {
	if n.Kind() == "command" {
		tokens := normalizeCommandTokens(shellWords(n.Utf8Text(src)))
		if len(tokens) > 0 {
			*out = append(*out, tokens)
		}
		return
	}
	for i := uint(0); i < n.ChildCount(); i++ {
		child := n.Child(i)
		if child != nil {
			collectCommands(child, src, out)
		}
	}
}

func walk(n *tree_sitter.Node, visit func(*tree_sitter.Node)) {
	if n == nil {
		return
	}
	visit(n)
	for i := uint(0); i < n.ChildCount(); i++ {
		walk(n.Child(i), visit)
	}
}

func addFinding(report *Report, seen map[string]struct{}, file string, n *tree_sitter.Node, rule, severity, evidence, reason string) {
	pos := n.StartPosition()
	f := Finding{
		File:     file,
		Line:     int(pos.Row) + 1,
		Column:   int(pos.Column) + 1,
		Rule:     rule,
		Severity: severity,
		Evidence: trimEvidence(evidence),
		Reason:   reason,
	}
	key := fmt.Sprintf("%s:%d:%d:%s:%s", f.File, f.Line, f.Column, f.Rule, f.Evidence)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	report.Findings = append(report.Findings, f)
}

func installHooks(root, pkgbuild string) ([]string, []string, error) {
	src, err := os.ReadFile(pkgbuild)
	if err != nil {
		return nil, nil, err
	}
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_bash.Language())); err != nil {
		return nil, nil, err
	}
	tree := parser.Parse(src, nil)
	if tree == nil {
		return nil, nil, fmt.Errorf("tree-sitter parse returned no tree")
	}
	defer tree.Close()

	var hooks []string
	var incomplete []string
	seen := map[string]struct{}{}
	walk(tree.RootNode(), func(n *tree_sitter.Node) {
		if n.Kind() != "variable_assignment" {
			return
		}
		text := strings.TrimSpace(n.Utf8Text(src))
		if !strings.HasPrefix(text, "install=") {
			return
		}
		value := strings.TrimSpace(strings.TrimPrefix(text, "install="))
		line := int(n.StartPosition().Row) + 1
		hook, ok := staticShellWord(value)
		if !ok || hook == "" {
			incomplete = append(incomplete, fmt.Sprintf("install in PKGBUILD:%d contains shell expansion or unsupported syntax", line))
			return
		}
		if filepath.IsAbs(hook) || strings.Contains(hook, "\x00") {
			incomplete = append(incomplete, fmt.Sprintf("install in PKGBUILD:%d references unsafe path %q", line, hook))
			return
		}
		full := filepath.Clean(filepath.Join(root, hook))
		rel, err := filepath.Rel(root, full)
		if err != nil || strings.HasPrefix(rel, "..") || rel == "." || filepath.IsAbs(rel) {
			incomplete = append(incomplete, fmt.Sprintf("install in PKGBUILD:%d escapes package directory: %q", line, hook))
			return
		}
		if _, err := os.Stat(full); err != nil {
			incomplete = append(incomplete, fmt.Sprintf("install hook %s referenced at PKGBUILD:%d could not be read: %v", rel, line, err))
			return
		}
		if _, ok := seen[full]; ok {
			return
		}
		seen[full] = struct{}{}
		hooks = append(hooks, full)
	})
	sort.Strings(hooks)
	sort.Strings(incomplete)
	return hooks, incomplete, nil
}

func staticShellWord(s string) (string, bool) {
	words, complete := parseShellWords(s)
	if !complete || len(words) != 1 {
		return "", false
	}
	return words[0], true
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

func shellWords(s string) []string {
	var words []string
	var b strings.Builder
	inSingle, inDouble, escaped := false, false, false
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
		case '|', ';', '&', '<', '>':
			if !inSingle && !inDouble {
				flush()
				words = append(words, string(r))
				continue
			}
		}
		if unicode.IsSpace(r) && !inSingle && !inDouble {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	return words
}

func normalizeCommandTokens(tokens []string) []string {
	tokens = trimCommandDecorations(tokens)
	for len(tokens) > 0 {
		cmd := commandBase(tokens[0])
		switch cmd {
		case "env":
			tokens = trimEnv(tokens[1:])
		case "sudo", "doas", "command":
			tokens = trimCommandDecorations(tokens[1:])
		default:
			return tokens
		}
	}
	return nil
}

func trimCommandDecorations(tokens []string) []string {
	for len(tokens) > 0 {
		if strings.Contains(tokens[0], "=") && !strings.HasPrefix(tokens[0], "-") {
			tokens = tokens[1:]
			continue
		}
		if isRedirectOperator(tokens[0]) {
			if len(tokens) > 1 {
				tokens = tokens[2:]
			} else {
				tokens = tokens[1:]
			}
			continue
		}
		return tokens
	}
	return nil
}

func trimEnv(tokens []string) []string {
	for len(tokens) > 0 {
		t := tokens[0]
		if strings.Contains(t, "=") && !strings.HasPrefix(t, "-") {
			tokens = tokens[1:]
			continue
		}
		if strings.HasPrefix(t, "-") {
			tokens = tokens[1:]
			continue
		}
		break
	}
	return trimCommandDecorations(tokens)
}

func isRedirectOperator(s string) bool {
	return s == ">" || s == "<" || s == ">>" || s == "2>" || s == "&>"
}

func isShell(cmd string) bool {
	switch cmd {
	case "sh", "bash", "dash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

func isDownloader(cmd string) bool {
	switch cmd {
	case "curl", "wget", "fetch":
		return true
	default:
		return false
	}
}

func isThirdPartyInstall(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	cmd := commandBase(tokens[0])
	args := tokens[1:]
	switch cmd {
	case "npm", "yarn", "pnpm", "bun":
		return hasSubcommand(args, "install", "add", "i")
	case "pip", "pip3", "pipx":
		return hasSubcommand(args, "install")
	case "cargo":
		return hasSubcommand(args, "install")
	case "rustup":
		if len(args) >= 2 && args[0] == "component" && args[1] == "add" {
			return true
		}
		if len(args) >= 2 && args[0] == "toolchain" && args[1] == "install" {
			return true
		}
		return hasSubcommand(args, "default")
	case "go":
		return hasSubcommand(args, "install", "get")
	case "python", "python2", "python3":
		return hasPythonPipInstall(args)
	default:
		return false
	}
}

func hasSubcommand(args []string, subs ...string) bool {
	want := map[string]struct{}{}
	for _, sub := range subs {
		want[sub] = struct{}{}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		_, ok := want[arg]
		return ok
	}
	return false
}

func hasPythonPipInstall(args []string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "-m" && args[i+1] == "pip" && args[i+2] == "install" {
			return true
		}
	}
	return false
}

func hasFlag(args []string, flag string) bool {
	short := strings.TrimPrefix(flag, "-")
	for _, arg := range args {
		if arg == flag {
			return true
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.TrimPrefix(arg, "-"), short) {
			return true
		}
	}
	return false
}

func commandBase(cmd string) string {
	cmd = strings.Trim(cmd, "'\"")
	if cmd == "" {
		return ""
	}
	return filepath.Base(cmd)
}

func containsBase64Blob(text string) bool {
	for _, match := range base64BlobRE.FindAllString(text, -1) {
		if len(match)%4 != 0 {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(match); err == nil {
			return true
		}
	}
	return false
}

func trimEvidence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxEvidenceLen {
		return s
	}
	return s[:maxEvidenceLen-3] + "..."
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func sortReport(report *Report) {
	sort.Slice(report.Files, func(i, j int) bool {
		return report.Files[i].Path < report.Files[j].Path
	})
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Rule < b.Rule
	})
	sort.Strings(report.Incomplete)
}
