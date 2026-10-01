// Package review contains findings shared by recipe and artifact inspection.
package review

import (
	"fmt"
	"io"
	"strings"
	"unicode"
)

type Action string

const (
	Info   Action = "INFO"
	Review Action = "REVIEW"
	Block  Action = "BLOCK"
)

type Finding struct {
	Rule     string `json:"rule"`
	Action   Action `json:"action"`
	Location string `json:"location,omitempty"`
	Evidence string `json:"evidence"`
}

type Report struct {
	Findings []Finding `json:"findings"`
}

func (r *Report) Add(rule string, action Action, location, evidence string) {
	r.Findings = append(r.Findings, Finding{rule, action, location, evidence})
}
func (r Report) Has(action Action) bool {
	for _, f := range r.Findings {
		if f.Action == action {
			return true
		}
	}
	return false
}
func (r Report) Print(w io.Writer) {
	for _, f := range r.Findings {
		fmt.Fprintf(w, "%s  %s: %s\n", f.Action, Safe(f.Location), Safe(f.Evidence))
	}
}

// Safe preserves readable diffs while escaping terminal controls and bidi marks.
func Safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (!unicode.IsControl(r) && !unicode.Is(unicode.Cf, r)) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

// Answer reads exactly one line so a later interactive subprocess retains stdin.
func Answer(r io.Reader) (string, error) {
	var b strings.Builder
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return strings.ToLower(strings.TrimSpace(b.String())), nil
			}
			if b.Len() >= 4096 {
				return "", fmt.Errorf("answer exceeds limit")
			}
			b.WriteByte(one[0])
		}
		if err != nil {
			return "", err
		}
	}
}
