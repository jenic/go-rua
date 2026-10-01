package install

import (
	"bytes"
	"strings"
	"testing"

	"go-rua/internal/review"
)

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
