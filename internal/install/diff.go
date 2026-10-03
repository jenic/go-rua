package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
	"go-rua/internal/term"
)

func recipeDiff(old, next reviewstate.Snapshot) (string, error) {
	before, after := map[string]reviewstate.File{}, map[string]reviewstate.File{}
	names := map[string]bool{}
	for _, f := range old {
		before[f.Path], names[f.Path] = f, true
	}
	for _, f := range next {
		after[f.Path], names[f.Path] = f, true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	var b strings.Builder
	var dir string
	defer func() {
		if dir != "" {
			os.RemoveAll(dir)
		}
	}()
	for _, name := range ordered {
		a, existsBefore := before[name]
		z, existsAfter := after[name]
		if existsBefore == existsAfter && a.Mode == z.Mode && bytes.Equal(a.Data, z.Data) {
			continue
		}
		fmt.Fprintf(&b, "--- installed/%s (mode %04o)\n+++ candidate/%s (mode %04o)\n", name, a.Mode, name, z.Mode)
		// Headers retain additions/removals of empty files and mode-only changes.
		if bytes.Equal(a.Data, z.Data) {
			continue
		}
		if dir == "" {
			var err error
			dir, err = os.MkdirTemp("", "go-rua-diff-*")
			if err != nil {
				return "", fmt.Errorf("create recipe diff directory: %w", err)
			}
		}
		hunks, err := recipeFileHunks(dir, a.Data, z.Data)
		if err != nil {
			return "", fmt.Errorf("diff recipe input %q: %w", name, err)
		}
		b.WriteString(hunks)
	}
	if b.Len() == 0 {
		return "Recipe is unchanged from the confirmed installed baseline.\n", nil
	}
	return b.String(), nil
}

func recipeFileHunks(dir string, before, after []byte) (string, error) {
	// Use fixed private filenames: recipe paths never become command arguments.
	for _, f := range []struct {
		name string
		data []byte
	}{{"installed", before}, {"candidate", after}} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0600); err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "--no-pager", "diff", "--no-index",
		"--no-ext-diff", "--no-textconv", "--no-color", "--text", "--no-renames",
		"--diff-algorithm=myers", "--no-indent-heuristic", "--unified=3",
		"--inter-hunk-context=0", "--word-diff=none", "--no-prefix",
		"--output-indicator-old=-", "--output-indicator-new=+", "--output-indicator-context= ",
		"--", "installed", "candidate")
	cmd.Dir = dir
	// Neither user Git configuration nor inherited Git overrides may hide changes
	// or invoke helpers. --no-index reads files without writing Git metadata.
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "GIT_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C")
	var out, stderr boundedOutput
	out.max, stderr.max = reviewstate.MaxSnapshot*8, 64<<10
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return "", fmt.Errorf("git diff: %w: %s", err, stderr.String())
	}
	// Replace Git's temporary file headers with the snapshot paths and modes.
	start := strings.Index(out.String(), "\n@@ ")
	if start < 0 {
		return "", fmt.Errorf("git diff produced no hunks for changed content")
	}
	return out.String()[start+1:], nil
}

func printRecipeDiff(w io.Writer, diff string) {
	// Escape untrusted terminal sequences before adding our own formatting.
	safe := review.Safe(diff)
	if !term.EnabledFor(w) {
		fmt.Fprint(w, safe)
		return
	}
	lines := strings.SplitAfter(safe, "\n")
	highlights := inlineHighlights(lines)
	for i, line := range lines {
		text := strings.TrimSuffix(line, "\n")
		color := ""
		switch {
		case strings.HasPrefix(text, "-"):
			color = "\x1b[31m"
		case strings.HasPrefix(text, "+"):
			color = "\x1b[32m"
		}
		if color == "" {
			fmt.Fprint(w, text)
		} else if spans, ok := highlights[i]; ok {
			fmt.Fprint(w, color, text[:1])
			for _, span := range spans {
				if span.changed {
					fmt.Fprintf(w, "\x1b[1;7m%s\x1b[22;27m", span.text)
				} else {
					fmt.Fprint(w, span.text)
				}
			}
			fmt.Fprint(w, "\x1b[0m")
		} else {
			fmt.Fprintf(w, "%s%s\x1b[0m", color, text)
		}
		if strings.HasSuffix(line, "\n") {
			fmt.Fprint(w, "\n")
		}
	}
}

type inlineSpan struct {
	text    string
	changed bool
}

// Highlight individual character edits in equally sized replacement blocks.
// Unequal blocks retain line colors rather than pairing unrelated lines.
func inlineHighlights(lines []string) map[int][]inlineSpan {
	spans := map[int][]inlineSpan{}
	oldLeft, newLeft := 0, 0
	for i := 0; i < len(lines); {
		line := strings.TrimSuffix(lines[i], "\n")
		if a, z, ok := hunkCounts(line); ok {
			oldLeft, newLeft = a, z
			i++
			continue
		}
		if oldLeft == 0 && newLeft == 0 {
			i++
			continue
		}
		if oldLeft > 0 && strings.HasPrefix(line, "-") {
			var removed, added []int
			for i < len(lines) {
				if strings.HasPrefix(lines[i], "\\ No newline") {
					i++
				} else if oldLeft > 0 && strings.HasPrefix(lines[i], "-") {
					removed = append(removed, i)
					oldLeft--
					i++
				} else {
					break
				}
			}
			for i < len(lines) {
				if strings.HasPrefix(lines[i], "\\ No newline") {
					i++
				} else if newLeft > 0 && strings.HasPrefix(lines[i], "+") {
					added = append(added, i)
					newLeft--
					i++
				} else {
					break
				}
			}
			if len(removed) == len(added) {
				for j, r := range removed {
					a := added[j]
					x, y := changedSpans(strings.TrimSuffix(lines[r][1:], "\n"), strings.TrimSuffix(lines[a][1:], "\n"))
					if len(x) > 0 {
						spans[r] = x
					}
					if len(y) > 0 {
						spans[a] = y
					}
				}
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			oldLeft--
			newLeft--
		} else if strings.HasPrefix(line, "+") {
			newLeft--
		}
		i++
	}
	return spans
}

func hunkCounts(line string) (int, int, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] != "@@" || fields[3] != "@@" || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, false
	}
	count := func(field string) (int, error) {
		_, n, ok := strings.Cut(field, ",")
		if !ok {
			return 1, nil
		}
		return strconv.Atoi(n)
	}
	a, errA := count(fields[1])
	z, errZ := count(fields[2])
	return a, z, errA == nil && errZ == nil && a >= 0 && z >= 0
}

func changedSpans(old, next string) ([]inlineSpan, []inlineSpan) {
	a, z := []rune(old), []rune(next)
	prefix := 0
	for prefix < len(a) && prefix < len(z) && a[prefix] == z[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(z)-prefix && a[len(a)-1-suffix] == z[len(z)-1-suffix] {
		suffix++
	}
	x, y := a[prefix:len(a)-suffix], z[prefix:len(z)-suffix]
	removed, added := make([]bool, len(a)), make([]bool, len(z))
	if len(x) == 0 || len(y) == 0 {
		for i := range x {
			removed[prefix+i] = true
		}
		for j := range y {
			added[prefix+j] = true
		}
	} else {
		// Bound work and memory for unusually long, unrelated lines. They retain
		// the ordinary red/green line colors without imprecise inline highlights.
		const maxInlineCells = 1 << 20
		width := len(y) + 1
		if len(x)+1 > maxInlineCells/width {
			return nil, nil
		}
		// Find a longest common character subsequence so unchanged text between
		// separate edits stays unhighlighted, including Unicode characters.
		common := make([]uint32, (len(x)+1)*width)
		for i := len(x) - 1; i >= 0; i-- {
			for j := len(y) - 1; j >= 0; j-- {
				cell := i*width + j
				if x[i] == y[j] {
					common[cell] = 1 + common[cell+width+1]
				} else {
					common[cell] = max(common[cell+width], common[cell+1])
				}
			}
		}
		i, j := 0, 0
		for i < len(x) || j < len(y) {
			if i < len(x) && j < len(y) && x[i] == y[j] {
				i++
				j++
			} else if i < len(x) && (j == len(y) || common[(i+1)*width+j] >= common[i*width+j+1]) {
				removed[prefix+i] = true
				i++
			} else {
				added[prefix+j] = true
				j++
			}
		}
	}
	spans := func(r []rune, changed []bool) []inlineSpan {
		var result []inlineSpan
		for start := 0; start < len(r); {
			end := start + 1
			for end < len(r) && changed[end] == changed[start] {
				end++
			}
			result = append(result, inlineSpan{string(r[start:end]), changed[start]})
			start = end
		}
		return result
	}
	return spans(a, removed), spans(z, added)
}
