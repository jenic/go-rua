package install

import (
	"fmt"
	"sort"

	"go-rua/internal/aur"
	"go-rua/internal/pacman"
)

type Plan struct {
	Targets     []string
	BuildOrder  []string
	RepoMissing []string
	Unknown     []string
	// Depths assigns each AUR package name a depth where 0 are requested targets,
	// and larger numbers are deeper dependencies. Max depth builds first.
	Depths map[string]int
}

// BuildPlan resolves AUR targets and transitive AUR deps, determines repo deps
// to install, and returns a topologically sorted build order for AUR packages.
func BuildPlan(targets []string) (Plan, error) {
	if len(targets) == 0 {
		return Plan{}, nil
	}
	// closure over AUR deps (by exact name)
	infoByName := map[string]aur.Package{}
	toQuery := dedupCopy(targets)

	for len(toQuery) > 0 {
		infos, err := aur.Info(toQuery)
		if err != nil {
			return Plan{}, err
		}
		// record fetched, and collect candidate AUR deps by name
		candSet := map[string]struct{}{}
		for _, inf := range infos {
			if _, ok := infoByName[inf.Name]; ok {
				continue
			}
			infoByName[inf.Name] = inf
			for _, d := range append(append([]string{}, inf.Depends...), append(inf.MakeDepends, inf.CheckDepends...)...) {
				name := pacman.StripDepName(d)
				if name == "" {
					continue
				}
				if _, ok := infoByName[name]; ok {
					continue
				}
				candSet[name] = struct{}{}
			}
		}
		// prepare next query: only names not yet known to be in AUR
		toQuery = toQuery[:0]
		for n := range candSet {
			// ask AUR if this name exists by trying to fetch it in next round
			toQuery = append(toQuery, n)
		}
		// If candSet empty, loop ends
	}

	// Determine the set of AUR packages we plan to build
	aurNames := make([]string, 0, len(infoByName))
	for n := range infoByName {
		aurNames = append(aurNames, n)
	}
	sort.Strings(aurNames)

	// Build edges: dep -> pkg for AUR-only edges, and deps map: pkg -> deps (AUR-only)
	edges := map[string][]string{}
	indeg := map[string]int{}
	deps := map[string][]string{}
	for _, n := range aurNames {
		indeg[n] = 0
	}
	for _, inf := range infoByName {
		for _, d := range append(append([]string{}, inf.Depends...), append(inf.MakeDepends, inf.CheckDepends...)...) {
			dn := pacman.StripDepName(d)
			if _, ok := infoByName[dn]; ok {
				edges[dn] = append(edges[dn], inf.Name)
				indeg[inf.Name]++
				deps[inf.Name] = append(deps[inf.Name], dn)
			}
		}
	}

	order, err := topoSort(aurNames, edges, indeg)
	if err != nil {
		return Plan{}, fmt.Errorf("dependency cycle: %w", err)
	}

	// Repo missing vs unknown for non-AUR deps
	nonAurDeps := map[string]struct{}{}
	for _, inf := range infoByName {
		for _, d := range append(append([]string{}, inf.Depends...), append(inf.MakeDepends, inf.CheckDepends...)...) {
			dn := pacman.StripDepName(d)
			if _, ok := infoByName[dn]; ok {
				continue
			}
			nonAurDeps[dn] = struct{}{}
		}
	}
	depNames := make([]string, 0, len(nonAurDeps))
	for n := range nonAurDeps {
		depNames = append(depNames, n)
	}
	sort.Strings(depNames)

	missing, err := pacman.CheckMissing(depNames)
	if err != nil {
		return Plan{}, err
	}
	missSet := map[string]struct{}{}
	for _, m := range missing {
		missSet[pacman.StripDepName(m)] = struct{}{}
	}

	var repoMissing, unknown []string
	for _, n := range depNames {
		if _, m := missSet[n]; !m {
			continue
		}
		isRepo, err := pacman.IsRepoPackage(n)
		if err != nil {
			unknown = append(unknown, n)
			continue
		}
		if isRepo {
			repoMissing = append(repoMissing, n)
		} else {
			unknown = append(unknown, n)
		}
	}

	// Compute depths from targets: distance through deps (pkg -> deps)
	depths := map[string]int{}
	// initialize known nodes to 0; targets start at 0 explicitly
	for _, n := range aurNames {
		depths[n] = 0
	}
	// mark requested targets
	tset := map[string]struct{}{}
	for _, t := range targets {
		if _, ok := infoByName[t]; ok {
			tset[t] = struct{}{}
		}
	}
	// BFS-like propagation: from each target, deps get +1, taking max across paths
	queue := make([]string, 0, len(tset))
	for t := range tset {
		queue = append(queue, t)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, d := range deps[cur] {
			if depths[d] < depths[cur]+1 {
				depths[d] = depths[cur] + 1
				queue = append(queue, d)
			}
		}
	}

	return Plan{
		Targets:     dedupCopy(targets),
		BuildOrder:  order,
		RepoMissing: repoMissing,
		Unknown:     unknown,
		Depths:      depths,
	}, nil
}

func topoSort(nodes []string, edges map[string][]string, indeg map[string]int) ([]string, error) {
	q := make([]string, 0)
	for _, n := range nodes {
		if indeg[n] == 0 {
			q = append(q, n)
		}
	}
	// stable order: keep queue sorted
	sort.Strings(q)
	out := []string{}
	visited := 0
	for len(q) > 0 {
		// pop front
		n := q[0]
		q = q[1:]
		out = append(out, n)
		visited++
		for _, m := range edges[n] {
			indeg[m]--
			if indeg[m] == 0 {
				q = append(q, m)
				sort.Strings(q)
			}
		}
	}
	if visited != len(nodes) {
		return nil, fmt.Errorf("cycle detected")
	}
	return out, nil
}

func dedupCopy(ss []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
