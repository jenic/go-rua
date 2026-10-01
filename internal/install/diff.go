package install

import (
	"fmt"
	"io"
	"strings"

	"go-rua/internal/review"
	"go-rua/internal/term"
)

func printRecipeDiff(w io.Writer, diff string) {
	// Escape untrusted terminal sequences before adding our own formatting.
	safe := review.Safe(diff)
	if !term.EnabledFor(w) {
		fmt.Fprint(w, safe)
		return
	}
	for line := range strings.SplitAfterSeq(safe, "\n") {
		text := strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(text, "-"):
			fmt.Fprintf(w, "\x1b[31m%s\x1b[0m", text)
		case strings.HasPrefix(text, "+"):
			fmt.Fprintf(w, "\x1b[32m%s\x1b[0m", text)
		default:
			fmt.Fprint(w, text)
		}
		if strings.HasSuffix(line, "\n") {
			fmt.Fprint(w, "\n")
		}
	}
}
