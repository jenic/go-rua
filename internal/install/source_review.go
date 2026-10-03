package install

import (
	"strings"

	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
)

// rememberedSourceReport changes only the displayed report. Keep the original
// REVIEW findings in the next installation record so approvals remain reusable.
func rememberedSourceReport(base string, fetched review.Report, baseline *reviewstate.Record) review.Report {
	if baseline == nil || baseline.Base != base {
		return fetched
	}
	approved := map[string]bool{}
	for _, f := range baseline.Accepted {
		if key, ok := redirectApprovalKey(f); ok {
			approved[key] = true
		}
	}
	displayed := review.Report{Findings: append([]review.Finding(nil), fetched.Findings...)}
	for i, f := range displayed.Findings {
		if key, ok := redirectApprovalKey(f); ok && approved[key] {
			displayed.Findings[i].Action = review.Info
			displayed.Findings[i].Evidence += " (previously accepted)"
		}
	}
	return displayed
}

func redirectApprovalKey(f review.Finding) (string, bool) {
	if f.Rule != "source-redirect" || f.Action != review.Review {
		return "", false
	}
	// The downloader generates this evidence from HTTPS URL.Host values. Match
	// the host pair independently of versioned filenames, preserving ports.
	evidence, ok := strings.CutPrefix(f.Evidence, "download redirected from ")
	if !ok {
		return "", false
	}
	from, to, ok := strings.Cut(evidence, " to ")
	if !ok || from == "" || to == "" || strings.ContainsAny(from+to, " \t\r\n\x00") {
		return "", false
	}
	return strings.ToLower(from) + "\x00" + strings.ToLower(to), true
}
