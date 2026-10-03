package install

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go-rua/internal/pacman"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
	"go-rua/internal/tarcheck"
)

func TestRecipeDiff(t *testing.T) {
	file := func(data string, mode uint32) reviewstate.Snapshot {
		return reviewstate.Snapshot{{Path: "PKGBUILD", Mode: mode, Data: []byte(data)}}
	}
	header := "--- installed/PKGBUILD (mode 0644)\n+++ candidate/PKGBUILD (mode 0644)\n"
	for _, tc := range []struct {
		name      string
		old, next reviewstate.Snapshot
		want      string
	}{
		{"unchanged", file("pkgver=1\n", 0644), file("pkgver=1\n", 0644), "Recipe is unchanged from the confirmed installed baseline.\n"},
		{"one line change", file("pkgname=app\npkgver=1\npkgrel=1\n", 0644), file("pkgname=app\npkgver=2\npkgrel=1\n", 0644), header + "@@ -1,3 +1,3 @@\n pkgname=app\n-pkgver=1\n+pkgver=2\n pkgrel=1\n"},
		{"insert line", file("a\nz\n", 0644), file("a\nb\nz\n", 0644), header + "@@ -1,2 +1,3 @@\n a\n+b\n z\n"},
		{"remove line", file("a\nb\nz\n", 0644), file("a\nz\n", 0644), header + "@@ -1,3 +1,2 @@\n a\n-b\n z\n"},
		{"first review", nil, file("pkgname=app\n", 0644), "--- installed/PKGBUILD (mode 0000)\n+++ candidate/PKGBUILD (mode 0644)\n@@ -0,0 +1 @@\n+pkgname=app\n"},
		{"deleted file", file("pkgname=app\n", 0644), nil, "--- installed/PKGBUILD (mode 0644)\n+++ candidate/PKGBUILD (mode 0000)\n@@ -1 +0,0 @@\n-pkgname=app\n"},
		{"empty file added", nil, file("", 0644), "--- installed/PKGBUILD (mode 0000)\n+++ candidate/PKGBUILD (mode 0644)\n"},
		{"empty file deleted", file("", 0644), nil, "--- installed/PKGBUILD (mode 0644)\n+++ candidate/PKGBUILD (mode 0000)\n"},
		{"mode only", file("same\n", 0644), file("same\n", 0755), "--- installed/PKGBUILD (mode 0644)\n+++ candidate/PKGBUILD (mode 0755)\n"},
		{"empty to content", file("", 0644), file("x\n", 0644), header + "@@ -0,0 +1 @@\n+x\n"},
		{"final newline added", file("same", 0644), file("same\n", 0644), header + "@@ -1 +1 @@\n-same\n\\ No newline at end of file\n+same\n"},
		{"final newline removed", file("same\n", 0644), file("same", 0644), header + "@@ -1 +1 @@\n-same\n+same\n\\ No newline at end of file\n"},
		{"binary bytes", file("a\x00b\n", 0644), file("a\x00c\n", 0644), header + "@@ -1 +1 @@\n-a\x00b\n+a\x00c\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := recipeDiff(tc.old, tc.next)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("diff = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecipeDiffSeparateHunksAndSortedFiles(t *testing.T) {
	var content strings.Builder
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&content, "line %d\n", i)
	}
	old := reviewstate.Snapshot{{Path: "z.patch", Mode: 0644, Data: []byte(content.String())}, {Path: "PKGBUILD", Mode: 0644, Data: []byte("unchanged\n")}}
	changed := strings.ReplaceAll(strings.ReplaceAll(content.String(), "line 5\n", "changed 5\n"), "line 25\n", "changed 25\n")
	next := reviewstate.Snapshot{{Path: "z.patch", Mode: 0644, Data: []byte(changed)}, {Path: "PKGBUILD", Mode: 0644, Data: []byte("unchanged\n")}, {Path: "a.patch", Mode: 0644, Data: []byte("new\n")}}
	diff, err := recipeDiff(old, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@@ -2,7 +2,7 @@", "@@ -22,7 +22,7 @@", "-line 5\n+changed 5\n", "-line 25\n+changed 25\n"} {
		if !strings.Contains(diff, want) {
			t.Fatalf("missing %q:\n%s", want, diff)
		}
	}
	if strings.Contains(diff, "PKGBUILD") || strings.Contains(diff, "line 15") || strings.Index(diff, "installed/a.patch") > strings.Index(diff, "installed/z.patch") {
		t.Fatalf("unchanged content or unsorted files:\n%s", diff)
	}
}

func TestRecipeDiffIgnoresGitOverrides(t *testing.T) {
	config := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(config, []byte("[diff]\n\texternal = /does-not-exist\n\twordDiff = color\n\tnoprefix = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", config)
	t.Setenv("GIT_EXTERNAL_DIFF", "/does-not-exist")
	t.Setenv("GIT_DIFF_OPTS", "--unified=0")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "diff.external")
	t.Setenv("GIT_CONFIG_VALUE_0", "/does-not-exist")
	old := reviewstate.Snapshot{{Path: "PKGBUILD", Mode: 0644, Data: []byte("context\nold\n")}}
	next := reviewstate.Snapshot{{Path: "PKGBUILD", Mode: 0644, Data: []byte("context\nnew\n")}}
	diff, err := recipeDiff(old, next)
	if err != nil || !strings.Contains(diff, " context\n-old\n+new\n") || strings.ContainsRune(diff, '\x1b') {
		t.Fatalf("Git configuration affected diff: %v %q", err, diff)
	}
}

func TestGuidedDiffFailureStopsBeforeApproval(t *testing.T) {
	p, opt, output, events := guidedFixture(t, "a\n")
	t.Setenv("PATH", t.TempDir())
	if err := GuidedUpgrade([]string{"app"}, p, opt); err == nil {
		t.Fatal("missing Git accepted")
	}
	if got := strings.Join(*events, ","); got != "candidate" || strings.Contains(output.String(), "[A] Approve") {
		t.Fatalf("failed diff reached approval/build: %s\n%s", got, output.String())
	}
}

func TestGuidedDiffUsesConfirmedBaseline(t *testing.T) {
	t.Setenv("RUA_COLOR", "never")
	p, opt, output, events := guidedFixture(t, "d\ns\n")
	c, err := prepareCandidateFn(p.ReviewDir("app"), "app")
	if err != nil {
		t.Fatal(err)
	}
	var baseline reviewstate.Snapshot
	for _, f := range c.recipe {
		f.Data = bytes.ReplaceAll(f.Data, []byte("2"), []byte("1"))
		baseline = append(baseline, f)
	}
	store, err := reviewstate.Open(p.ReviewStateDir())
	if err != nil {
		t.Fatal(err)
	}
	err = store.Save(reviewstate.Record{
		Schema: 1, Policy: reviewstate.PolicyVersion, Base: "app", Commit: c.commit,
		Recipe: baseline, EffectiveRecipe: baseline, InstalledAt: "2026-01-01T00:00:00Z",
		Artifacts: []tarcheck.Manifest{{Name: "app", Version: "1-1", SHA256: strings.Repeat("a", 64)}},
	}, false)
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	*events = nil
	if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, "-pkgver=1\n+pkgver=2\n") != 2 || strings.Count(text, " pkgname=app\n") != 2 || strings.Contains(text, "+pkgname=app\n") || strings.Contains(text, "-pkgname=app\n") {
		t.Fatalf("expected initial and redisplayed line diff against baseline:\n%s", text)
	}
	if got := strings.Join(*events, ","); got != "candidate" {
		t.Fatalf("skip reached build: %s", got)
	}
	// Installed-version drift invalidates the baseline and forces full review.
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": "0-1"}}, nil
	}
	opt.Input = strings.NewReader("s\n")
	output.Reset()
	if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "+pkgname=app\n") {
		t.Fatalf("installed-version drift did not force full review:\n%s", output.String())
	}
}

func TestPrintRecipeDiff(t *testing.T) {
	for _, tc := range []struct {
		name, input, colored string
	}{
		{name: "empty"},
		{name: "unchanged", input: "Recipe is unchanged.\n", colored: "Recipe is unchanged.\n"},
		{name: "headers and lines", input: "--- installed/x\n+++ candidate/x\n-old\n+new\n context\n", colored: "\x1b[31m--- installed/x\x1b[0m\n\x1b[32m+++ candidate/x\x1b[0m\n\x1b[31m-old\x1b[0m\n\x1b[32m+new\x1b[0m\n context\n"},
		{name: "no trailing newline", input: "+new", colored: "\x1b[32m+new\x1b[0m"},
		{name: "blank lines", input: "\n+\n\n", colored: "\n\x1b[32m+\x1b[0m\n\n"},
		{name: "terminal injection", input: "+\x1b[2J\x1b]8;;https://example.com\a\r\u202e\ttext\n", colored: "+\\u001b[2J\\u001b]8;;https://example.com\\u0007\\u000d\\u202e\ttext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "terminal injection" {
				tc.colored = "\x1b[32m" + tc.colored + "\x1b[0m\n"
			}
			for _, mode := range []string{"always", "never"} {
				t.Run(mode, func(t *testing.T) {
					t.Setenv("RUA_COLOR", mode)
					var output bytes.Buffer
					printRecipeDiff(&output, tc.input)
					want := tc.colored
					if mode == "never" {
						want = review.Safe(tc.input)
					}
					if got := output.String(); got != want {
						t.Fatalf("output = %q, want %q", got, want)
					}
					plain := strings.NewReplacer("\x1b[31m", "", "\x1b[32m", "", "\x1b[0m", "").Replace(output.String())
					if plain != review.Safe(tc.input) || strings.ContainsRune(plain, '\x1b') {
						t.Fatalf("sanitized content changed: %q", plain)
					}
				})
			}
		})
	}
}

func TestPrintRecipeDiffInlineHighlights(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		marked      []string
	}{
		{"version", "@@ -1 +1 @@\n-pkgver=1.2\n+pkgver=1.3\n", []string{"\x1b[1;7m2\x1b[22;27m", "\x1b[1;7m3\x1b[22;27m"}},
		{"unicode", "@@ -1 +1 @@\n-label=猫尾\n+label=犬尾\n", []string{"\x1b[1;7m猫\x1b[22;27m", "\x1b[1;7m犬\x1b[22;27m"}},
		{"insert within line", "@@ -1 +1 @@\n-abc\n+abXc\n", []string{"\x1b[1;7mX\x1b[22;27m"}},
		{"remove within line", "@@ -1 +1 @@\n-abXc\n+abc\n", []string{"\x1b[1;7mX\x1b[22;27m"}},
		{"no final newline", "@@ -1 +1 @@\n-pkgver=1\n\\ No newline at end of file\n+pkgver=2\n\\ No newline at end of file\n", []string{"\x1b[1;7m1\x1b[22;27m", "\x1b[1;7m2\x1b[22;27m"}},
		{"multiple paired lines", "@@ -1,2 +1,2 @@\n-a=1\n-b=1\n+a=2\n+b=3\n", []string{"\x1b[1;7m2\x1b[22;27m", "\x1b[1;7m3\x1b[22;27m"}},
		{"unequal blocks", "@@ -1 +1,2 @@\n-old\n+new\n+extra\n", nil},
		{"headers", "--- installed/a\n+++ candidate/a\n", nil},
		{"header-like content", "@@ -1 +1 @@\n--- value=1\n+++ value=2\n", []string{"\x1b[1;7m--\x1b[22;27m", "\x1b[1;7m1\x1b[22;27m", "\x1b[1;7m++\x1b[22;27m", "\x1b[1;7m2\x1b[22;27m"}},
		{"escape sequences", "@@ -1 +1 @@\n-x=1\x1b[2J\r\u202e\n+x=2\x1b[2J\r\u202e\n", []string{"\x1b[1;7m1\x1b[22;27m", "\x1b[1;7m2\x1b[22;27m"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"always", "never"} {
				t.Run(mode, func(t *testing.T) {
					t.Setenv("RUA_COLOR", mode)
					var output bytes.Buffer
					printRecipeDiff(&output, tc.input)
					got := output.String()
					if mode == "always" {
						for _, mark := range tc.marked {
							if !strings.Contains(got, mark) {
								t.Fatalf("missing %q in %q", mark, got)
							}
						}
						if len(tc.marked) == 0 && strings.Contains(got, "\x1b[1;7m") {
							t.Fatalf("unexpected inline highlight: %q", got)
						}
					}
					plain := strings.NewReplacer("\x1b[31m", "", "\x1b[32m", "", "\x1b[0m", "", "\x1b[1;7m", "", "\x1b[22;27m", "").Replace(got)
					if plain != review.Safe(tc.input) || strings.ContainsRune(plain, '\x1b') || (mode == "never" && got != plain) {
						t.Fatalf("sanitized content changed: %q", got)
					}
				})
			}
		})
	}
}

func TestChangedSpansCharacterEdits(t *testing.T) {
	for _, tc := range []struct {
		name, old, next   string
		removed, inserted []string
	}{
		{
			"version repeated in URL",
			"0-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.96.60/brave-origin-1.96.60",
			"1-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.96.61/brave-origin-1.96.61",
			[]string{"0", "0", "0"}, []string{"1", "1", "1"},
		},
		{"separate substitutions", "a1-b2-c3", "a4-b5-c6", []string{"1", "2", "3"}, []string{"4", "5", "6"}},
		{"mixed edits", "abXcdYef", "abcdZef", []string{"X", "Y"}, []string{"Z"}},
		{"unicode edits", "label=猫/尾", "label=犬/毛", []string{"猫", "尾"}, []string{"犬", "毛"}},
		{"whitespace edits", "a b c", "a\tb  c", []string{" "}, []string{"\t", " "}},
		{"moved character", "abc", "bca", []string{"a"}, []string{"a"}},
		{"insert everything", "", "new", nil, []string{"new"}},
		{"remove everything", "old", "", []string{"old"}, nil},
		{"identical", "same", "same", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next := changedSpans(tc.old, tc.next)
			check := func(spans []inlineSpan, original string, want []string) string {
				t.Helper()
				var full, unchanged strings.Builder
				var marked []string
				for _, span := range spans {
					full.WriteString(span.text)
					if span.changed {
						marked = append(marked, span.text)
					} else {
						unchanged.WriteString(span.text)
					}
				}
				if full.String() != original || !reflect.DeepEqual(marked, want) {
					t.Fatalf("spans = %+v, want text %q and highlights %q", spans, original, want)
				}
				return unchanged.String()
			}
			before, after := check(old, tc.old, tc.removed), check(next, tc.next, tc.inserted)
			if before != after {
				t.Fatalf("unhighlighted characters differ: %q != %q", before, after)
			}
		})
	}
}

func TestPrintRecipeDiffSeparateCharacterEdits(t *testing.T) {
	t.Setenv("RUA_COLOR", "always")
	old := "0-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.96.60/brave-origin-1.96.60"
	next := "1-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.96.61/brave-origin-1.96.61"
	diff := "@@ -1 +1 @@\n-" + old + "\n+" + next + "\n"
	var output bytes.Buffer
	printRecipeDiff(&output, diff)
	const start, end = "\x1b[1;7m", "\x1b[22;27m"
	// Only the three edited digits should be marked, including in v1.96.61.
	// Other occurrences of '1' in unchanged version prefixes remain unmarked.
	wantNext := start + "1" + end + "-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.96.6" + start + "1" + end + "/brave-origin-1.96.6" + start + "1" + end
	want := "@@ -1 +1 @@\n\x1b[31m-" + strings.ReplaceAll(old, "0", start+"0"+end) + "\x1b[0m\n\x1b[32m+" + wantNext + "\x1b[0m\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestPrintRecipeDiffLongLineLimit(t *testing.T) {
	t.Setenv("RUA_COLOR", "always")
	old, next := strings.Repeat("x", 2000), strings.Repeat("y", 2000)
	var output bytes.Buffer
	printRecipeDiff(&output, "@@ -1 +1 @@\n-"+old+"\n+"+next+"\n")
	want := "@@ -1 +1 @@\n\x1b[31m-" + old + "\x1b[0m\n\x1b[32m+" + next + "\x1b[0m\n"
	if output.String() != want {
		t.Fatal("long-line limit changed the diff or added imprecise inline highlights")
	}
}

func TestGuidedDiffRedisplayColor(t *testing.T) {
	for _, mode := range []string{"always", "never"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("RUA_COLOR", mode)
			p, opt, output, events := guidedFixture(t, "d\na\na\n")
			if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			first := "--- installed/"
			last := "+pkgname=app\n"
			if mode == "always" {
				first = "\x1b[31m" + first
				last = "\x1b[32m+pkgname=app\x1b[0m\n"
			} else if strings.ContainsRune(text, '\x1b') {
				t.Fatal("plain workflow contains ANSI escapes")
			}
			if strings.Count(text, first+".SRCINFO") != 2 || strings.Count(text, last) != 2 {
				t.Fatalf("expected initial and redisplayed diff in mode %s:\n%s", mode, text)
			}
			if strings.Count(strings.Join(*events, ","), "install") != 1 {
				t.Fatalf("approval did not produce one installation: %v", *events)
			}
		})
	}
}
