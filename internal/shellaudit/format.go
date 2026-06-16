package shellaudit

import (
	"fmt"
	"strings"
)

// FormatReport renders shell audit warnings for terminal review.
func FormatReport(report Report) string {
	if !report.HasWarnings() {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nShell logic warnings:\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "  %s:%d:%d [%s/%s] %s\n", finding.File, finding.Line, finding.Column, finding.Rule, finding.Severity, finding.Reason)
		if finding.Evidence != "" {
			fmt.Fprintf(&b, "    evidence: %s\n", finding.Evidence)
		}
	}
	for _, msg := range report.Incomplete {
		fmt.Fprintf(&b, "  %s\n", msg)
	}
	b.WriteString("  Review these shell snippets carefully; these heuristics highlight risk but do not prove intent.\n")
	return b.String()
}
