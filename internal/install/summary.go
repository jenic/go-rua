package install

import (
	"fmt"
	"sort"
	"strings"

	"go-rua/internal/aur"
	"go-rua/internal/pacman"
)

// DepSummary describes dependency status for requested AUR targets.
type DepSummary struct {
	Targets     []string
	RepoMissing []string // repo packages not satisfied; install via pacman
	Unknown     []string // not in repos; may be AUR, provided, or virtual
	Satisfied   []string // already satisfied deps
}

// SummarizeForAUR resolves dependency names from AUR package info
// and classifies which are missing and available via pacman repos.
func SummarizeForAUR(pkgs []string, infos []aur.Package) (DepSummary, error) {
	targetSet := make(map[string]struct{}, len(pkgs))
	for _, n := range pkgs {
		targetSet[n] = struct{}{}
	}

	// gather depends from all packages
	allDeps := make(map[string]struct{})
	for _, inf := range infos {
		for _, d := range append(append([]string{}, inf.Depends...), append(inf.MakeDepends, inf.CheckDepends...)...) {
			name := pacman.StripDepName(d)
			if name == "" {
				continue
			}
			// ignore if this dep is one of the AUR targets (it will be built)
			if _, isTarget := targetSet[name]; isTarget {
				continue
			}
			allDeps[name] = struct{}{}
		}
	}
	depNames := make([]string, 0, len(allDeps))
	for n := range allDeps {
		depNames = append(depNames, n)
	}
	sort.Strings(depNames)

	// which are missing on system
	missing, err := pacman.CheckMissing(depNames)
	if err != nil {
		return DepSummary{}, err
	}
	missSet := map[string]struct{}{}
	for _, m := range missing {
		// pacman -T may echo with version ops; normalize
		missSet[pacman.StripDepName(m)] = struct{}{}
	}

	var satisfied []string
	for _, n := range depNames {
		if _, m := missSet[n]; !m {
			satisfied = append(satisfied, n)
		}
	}

	// classify missing as repo vs unknown
	var repoMissing, unknown []string
	for _, n := range depNames {
		if _, m := missSet[n]; !m {
			continue
		}
		isRepo, err := pacman.IsRepoPackage(n)
		if err != nil {
			// non-fatal; conservatively mark as unknown
			unknown = append(unknown, n)
			continue
		}
		if isRepo {
			repoMissing = append(repoMissing, n)
		} else {
			unknown = append(unknown, n)
		}
	}

	return DepSummary{
		Targets:     append([]string{}, pkgs...),
		RepoMissing: repoMissing,
		Unknown:     unknown,
		Satisfied:   satisfied,
	}, nil
}

// FormatSummary renders a compact human-readable summary.
func FormatSummary(s DepSummary) string {
	b := &strings.Builder{}
	fmt.Fprintln(b, "Summary:")
	fmt.Fprintf(b, "  AUR targets: %s\n", strings.Join(s.Targets, ", "))
	if len(s.RepoMissing) > 0 {
		fmt.Fprintf(b, "  Repo deps missing: %s\n", strings.Join(s.RepoMissing, ", "))
		fmt.Fprintf(b, "    Install: sudo pacman -S --needed %s\n", strings.Join(s.RepoMissing, " "))
	} else {
		fmt.Fprintln(b, "  Repo deps missing: none")
	}
	if len(s.Unknown) > 0 {
		fmt.Fprintf(b, "  Unknown deps (maybe AUR/virtual): %s\n", strings.Join(s.Unknown, ", "))
	}
	return b.String()
}
