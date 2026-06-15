package sourceaudit

import (
	"fmt"
	"strings"
)

// FormatReport renders source URL audit warnings for terminal review.
func FormatReport(report Report) string {
	if !report.HasWarnings() {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nSource URL warnings:\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "  %s %s\n", finding.Source.Location, finding.Source.Value)
		if finding.Host != "" {
			fmt.Fprintf(&b, "    host: %s\n", finding.Host)
		}
		if finding.ASCIIHost != "" && !strings.EqualFold(finding.ASCIIHost, finding.Host) {
			fmt.Fprintf(&b, "    IDNA/Punycode: %s\n", finding.ASCIIHost)
		}
		if finding.UnicodeHost != "" && !strings.EqualFold(finding.UnicodeHost, finding.Host) {
			fmt.Fprintf(&b, "    Unicode form: %s\n", finding.UnicodeHost)
		}
		if len(finding.Reasons) > 0 {
			fmt.Fprintf(&b, "    reasons: %s\n", strings.Join(finding.Reasons, "; "))
		}
		if len(finding.Codepoints) > 0 {
			fmt.Fprintf(&b, "    codepoints: %s\n", strings.Join(finding.Codepoints, ", "))
		}
	}
	for _, msg := range report.Incomplete {
		fmt.Fprintf(&b, "  %s\n", msg)
	}
	for _, msg := range report.Mismatches {
		fmt.Fprintf(&b, "  %s\n", msg)
	}
	b.WriteString("  Review these source URLs carefully; Unicode characters can spoof trusted domains.\n")
	return b.String()
}
