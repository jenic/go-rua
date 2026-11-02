package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-rua/internal/aur"
	"go-rua/internal/build"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/recipeaudit"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
	"go-rua/internal/shellutil"
	"go-rua/internal/tarcheck"
	"golang.org/x/sys/unix"
)

var (
	installedSnapshotFn    = pacman.InstalledSnapshot
	verifySourcesFn        = build.VerifySources
	fetchReviewedSourcesFn = build.FetchReviewedSources
	buildVerifiedFn        = build.BuildVerifiedDirectory
	inspectArtifactFn      = tarcheck.Inspect
	guidedCompareFn        = pacman.Vercmp
	guidedDepsFn           = pacman.CheckMissing
	prepareCandidateFn     = prepareCandidate
	mergeCandidateFn       = mergeCandidate
	guidedLintFn           = guidedLint
)
var errSkipped = errors.New("skipped by user")
var errQuit = errors.New("upgrade cancelled")

type outcome struct{ base, status, detail string }
type guidedSession struct {
	p       paths.Paths
	opt     Options
	in      io.Reader
	out     io.Writer
	store   *reviewstate.Store
	results []outcome
}

// GuidedUpgrade owns a single dependency plan and builds each package base once.
func GuidedUpgrade(targets []string, p paths.Paths, opt Options) error {
	if len(targets) == 0 {
		return fmt.Errorf("no upgrade targets")
	}
	if opt.NonInteractive {
		return fmt.Errorf("guided upgrade requires interactive recipe approval")
	}
	in, out := opt.Input, opt.Output
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	var plan Plan
	if opt.Plan != nil {
		plan = *opt.Plan
	} else {
		var err error
		plan, err = BuildPlan(targets)
		if err != nil {
			return err
		}
	}
	infos, err := aur.Info(plan.BuildOrder)
	if err != nil {
		return err
	}
	order, groups, err := baseOrder(plan, infos)
	if err != nil {
		return err
	}
	store, err := reviewstate.Open(p.ReviewStateDir())
	if err != nil {
		return err
	}
	defer store.Close()
	s := guidedSession{p: p, opt: opt, in: in, out: out, store: store}
	defer s.summary()
	failed := 0
	for _, base := range order {
		fmt.Fprintf(out, "\n==> Upgrade %s\n", review.Safe(base))
		status, err := s.upgrade(base, groups[base], targets)
		if errors.Is(err, errQuit) || errors.Is(err, io.EOF) {
			s.results = append(s.results, outcome{base, "cancelled", "approval was not granted"})
			return errQuit
		}
		if errors.Is(err, errSkipped) {
			s.results = append(s.results, outcome{base, "skipped", err.Error()})
			continue
		}
		if err != nil {
			failed++
			if status == "" {
				status = "blocked"
			}
			fmt.Fprintf(out, "%s: %s\n", strings.ToUpper(status), review.Safe(err.Error()))
			s.results = append(s.results, outcome{base, status, err.Error()})
			continue
		}
		s.results = append(s.results, outcome{base, status, ""})
	}
	if failed > 0 {
		return fmt.Errorf("%d package base(s) could not be upgraded", failed)
	}
	return nil
}
func (s *guidedSession) summary() {
	fmt.Fprintln(s.out, "\nUpgrade results:")
	for _, r := range s.results {
		fmt.Fprintf(s.out, "  %s: %s", review.Safe(r.base), r.status)
		if r.detail != "" {
			fmt.Fprintf(s.out, " (%s)", review.Safe(r.detail))
		}
		fmt.Fprintln(s.out)
	}
}

func baseOrder(plan Plan, infos []aur.Package) ([]string, map[string][]aur.Package, error) {
	byName := map[string]aur.Package{}
	groups := map[string][]aur.Package{}
	for _, p := range infos {
		if p.PackageBase == "" {
			p.PackageBase = p.Name
		}
		if !reviewstate.ValidName(p.Name) || !reviewstate.ValidName(p.PackageBase) {
			return nil, nil, fmt.Errorf("invalid package identity")
		}
		byName[p.Name] = p
	}
	for _, name := range plan.BuildOrder {
		p, ok := byName[name]
		if !ok {
			return nil, nil, fmt.Errorf("missing AUR metadata for %s", name)
		}
		groups[p.PackageBase] = append(groups[p.PackageBase], p)
	}
	var bases []string
	indeg := map[string]int{}
	edges := map[string][]string{}
	seen := map[string]bool{}
	for base, pkgs := range groups {
		bases = append(bases, base)
		if _, ok := indeg[base]; !ok {
			indeg[base] = 0
		}
		for _, p := range pkgs {
			for _, dep := range packageDeps(p) {
				other, ok := byName[pacman.StripDepName(dep)]
				if !ok || other.PackageBase == base {
					continue
				}
				key := other.PackageBase + "\x00" + base
				if seen[key] {
					continue
				}
				seen[key] = true
				edges[other.PackageBase] = append(edges[other.PackageBase], base)
				indeg[base]++
			}
		}
	}
	sort.Strings(bases)
	order, err := topoSort(bases, edges, indeg)
	return order, groups, err
}
func packageDeps(p aur.Package) []string {
	d := append([]string{}, p.Depends...)
	d = append(d, p.MakeDepends...)
	return append(d, p.CheckDepends...)
}

func developmentBase(pkgs []aur.Package) bool {
	for _, p := range pkgs {
		for _, suffix := range []string{"-git", "-hg", "-bzr", "-svn", "-cvs", "-darcs"} {
			if strings.HasSuffix(p.Name, suffix) {
				return true
			}
		}
	}
	return false
}

func (s *guidedSession) upgrade(base string, pkgs []aur.Package, targets []string) (string, error) {
	installed, err := installedSnapshotFn()
	if err != nil {
		return "blocked", err
	}
	requested := map[string]bool{}
	for _, name := range targets {
		requested[name] = true
	}
	satisfied := true
	for _, p := range pkgs {
		if requested[p.Name] || installed.Versions[p.Name] == "" {
			satisfied = false
			break
		}
		cmp, e := guidedCompareFn(installed.Versions[p.Name], p.Version)
		if e != nil {
			return "blocked", e
		}
		if cmp < 0 {
			satisfied = false
			break
		}
	}
	if satisfied {
		return "already satisfied", nil
	}
	var deps []string
	own := map[string]bool{}
	for _, p := range pkgs {
		own[p.Name] = true
	}
	for _, p := range pkgs {
		for _, d := range packageDeps(p) {
			if !own[pacman.StripDepName(d)] {
				deps = append(deps, d)
			}
		}
	}
	missing, err := guidedDepsFn(dedupCopy(deps))
	if err != nil {
		return "blocked", err
	}
	if len(missing) > 0 {
		return "blocked", fmt.Errorf("dependencies are unsatisfied (possibly skipped): %s", strings.Join(missing, ", "))
	}
	baseline := s.baseline(base, installed)
	reviewDir := s.p.ReviewDir(base)
	c, err := prepareCandidateFn(reviewDir, base)
	if err != nil {
		return "blocked", err
	}
	var before reviewstate.Snapshot
	if baseline != nil {
		before = baseline.EffectiveRecipe
	}
	var installedVersion string
	for _, p := range pkgs {
		if installed.Versions[p.Name] != "" {
			installedVersion = installed.Versions[p.Name]
			break
		}
	}
	diff, err := recipeDiff(before, c.recipe)
	if err != nil {
		return "failed", err
	}
	printRecipeDiff(s.out, diff)
	work, err := os.MkdirTemp(s.p.CacheBuildDir, "review-"+base+"-*")
	if err != nil {
		return "failed", err
	}
	defer os.RemoveAll(work)
	if err := c.recipe.Write(work); err != nil {
		return "failed", err
	}
	report := recipeaudit.Audit(before, c.recipe, installedVersion, (s.opt.Devel && developmentBase(pkgs)) || s.opt.UpstreamBases[base], guidedCompareFn)
	// AUR planning metadata must still match the fetched candidate before building.
	if data := c.recipe.Get(".SRCINFO"); data != nil {
		versions := recipeaudit.Fields(data, "pkgver")
		releases := recipeaudit.Fields(data, "pkgrel")
		epochs := recipeaudit.Fields(data, "epoch")
		if len(versions) != 1 || len(releases) != 1 {
			report.Add("candidate-version", review.Block, ".SRCINFO", "missing or ambiguous package version")
		} else {
			v := versions[0] + "-" + releases[0]
			if len(epochs) == 1 && epochs[0] != "0" {
				v = epochs[0] + ":" + v
			}
			for _, p := range pkgs {
				if p.Version != v {
					report.Add("candidate-version", review.Block, ".SRCINFO", "candidate differs from the AUR version used for planning; rerun upgrade")
				}
			}
		}
		// Dependencies declared by the fetched recipe must also be available.
		var actual []string
		for _, key := range []string{"depends", "makedepends", "checkdepends"} {
			actual = append(actual, recipeaudit.FieldsForArchitecture(data, key, build.HostArchitecture())...)
		}
		var external []string
		for _, d := range actual {
			if !own[pacman.StripDepName(d)] {
				external = append(external, d)
			}
		}
		if absent, e := guidedDepsFn(dedupCopy(external)); e != nil {
			report.Add("candidate-dependencies", review.Block, ".SRCINFO", e.Error())
		} else if len(absent) > 0 {
			report.Add("candidate-dependencies", review.Block, ".SRCINFO", "candidate requires unavailable dependencies: "+strings.Join(absent, ", ")+"; replan before continuing")
		}
	}
	if err := auditRecipe(work, &report); err != nil {
		return "blocked", err
	}
	lint := guidedLintFn(work, false)
	report.Findings = append(report.Findings, lint.Findings...)
	report.Print(s.out)
	if report.Has(review.Block) {
		return "blocked", fmt.Errorf("recipe checks block progression")
	}
	if err := s.approveRecipe(diff, report); err != nil {
		return "", err
	}
	// The recipe and local package state are checked again after human review.
	check, err := reviewstate.Capture(work, c.recipe.Names())
	if err != nil {
		return "blocked", err
	}
	if check.Digest() != c.recipe.Digest() {
		return "blocked", fmt.Errorf("recipe changed during approval")
	}
	fresh, err := installedSnapshotFn()
	if err != nil {
		return "blocked", err
	}
	for _, p := range pkgs {
		if fresh.Versions[p.Name] != installed.Versions[p.Name] {
			return "blocked", fmt.Errorf("installed %s changed during review", p.Name)
		}
	}
	if err := mergeCandidateFn(reviewDir, c); err != nil {
		return "blocked", err
	}
	buildDir, err := os.MkdirTemp(s.p.CacheBuildDir, "build-"+base+"-*")
	if err != nil {
		return "failed", err
	}
	// Retain failed build directories for diagnosis; successful builds are removed.
	if err := c.recipe.Write(buildDir); err != nil {
		return "failed", err
	}
	if s.opt.PrepareBuildCopy != nil {
		if err := s.opt.PrepareBuildCopy(base, reviewDir, buildDir); err != nil {
			return "blocked", err
		}
	}
	effective, err := reviewstate.Capture(buildDir, c.recipe.Names())
	if err != nil {
		return "blocked", err
	}
	if effective.Digest() != c.recipe.Digest() {
		var override review.Report
		if err := auditRecipe(buildDir, &override); err != nil {
			return "blocked", err
		}
		override.Print(s.out)
		if override.Has(review.Block) {
			return "blocked", fmt.Errorf("effective recipe audit failed")
		}
		// The upstream hook already obtains approval for its exact generated diff.
		if override.Has(review.Review) {
			return "blocked", fmt.Errorf("effective recipe has unresolved audit findings")
		}
	}
	fmt.Fprintln(s.out, "Fetching and verifying approved sources...")
	fetched, err := fetchReviewedSourcesFn(buildDir)
	if err != nil {
		return "failed", err
	}
	sourceReport := rememberedSourceReport(base, fetched, baseline)
	sourceReport.Print(s.out)
	if sourceReport.Has(review.Review) {
		fmt.Fprint(s.out, "Source findings require review. Type 'accept sources' to continue, or 'skip': ")
		answer, err := review.Answer(s.in)
		if err != nil {
			return "", err
		}
		if answer != "accept sources" {
			return "", errSkipped
		}
	}
	verified, err := verifySourcesFn(buildDir, !s.opt.DisableSeccomp)
	if err != nil {
		return "failed", err
	}
	verified.Print(s.out)
	check, err = reviewstate.Capture(buildDir, effective.Names())
	if err != nil {
		return "blocked", err
	}
	if check.Digest() != effective.Digest() {
		return "blocked", fmt.Errorf("recipe changed during source verification")
	}
	fmt.Fprintln(s.out, "Building approved recipe...")
	if err := buildVerifiedFn(buildDir, s.p, s.opt.Offline, s.opt.Force, !s.opt.DisableSeccomp); err != nil {
		return "failed", fmt.Errorf("build failed at %s: %w", buildDir, err)
	}
	stage, err := os.MkdirTemp(s.p.DataCheckedTars, base+"-*")
	if err != nil {
		return "failed", err
	}
	artifacts, pathsByName, accepted, err := s.inspect(base, pkgs, buildDir, stage, baseline, effective)
	if err != nil {
		return "blocked", err
	}
	allFindings := append(append([]review.Finding{}, report.Findings...), accepted...)
	allFindings = append(allFindings, fetched.Findings...)
	allFindings = append(allFindings, verified.Findings...)
	record := reviewstate.Record{Schema: 1, Policy: reviewstate.PolicyVersion, Base: base, Commit: c.commit, Recipe: c.recipe, EffectiveRecipe: effective, Artifacts: artifacts, Accepted: allFindings}
	if err := s.store.Save(record, true); err != nil {
		return "blocked", err
	}
	if !s.opt.InstallBuilt {
		fmt.Fprintf(s.out, "Artifacts staged at %s\n", stage)
		return "staged", nil
	}
	// Install newly introduced dependencies as dependencies; preserve existing reasons.
	targetSet := map[string]bool{}
	for _, t := range targets {
		targetSet[t] = true
	}
	groups := map[bool][]string{}
	for _, a := range artifacts {
		asDeps := s.opt.AsDeps || (installed.Versions[a.Name] == "" && !targetSet[a.Name])
		groups[asDeps] = append(groups[asDeps], pathsByName[a.Name])
	}
	for _, asDeps := range []bool{true, false} {
		files := groups[asDeps]
		if len(files) == 0 {
			continue
		}
		current, e := installedSnapshotFn()
		if e != nil {
			return "blocked", e
		}
		acceptedFindings := map[review.Finding]bool{}
		for _, f := range accepted {
			acceptedFindings[f] = true
		}
		for _, a := range artifacts {
			// A previous split-package transaction in this session may have completed.
			if current.Versions[a.Name] != installed.Versions[a.Name] {
				return "blocked", fmt.Errorf("installed %s changed after review", a.Name)
			}
			var old *tarcheck.Manifest
			if baseline != nil {
				for i := range baseline.Artifacts {
					if baseline.Artifacts[i].Name == a.Name {
						old = &baseline.Artifacts[i]
						break
					}
				}
			}
			check := tarcheck.Compare(a, old, current.Files[a.Name], current.Owners, os.Lstat)
			for _, f := range check.Findings {
				if f.Action == review.Block || (f.Action == review.Review && !acceptedFindings[f]) {
					return "blocked", fmt.Errorf("filesystem or ownership changed after inspection: %s: %s", f.Location, f.Evidence)
				}
			}
		}
		for _, a := range artifacts {
			digest, e := tarcheck.Digest(pathsByName[a.Name])
			if e != nil {
				return "blocked", e
			}
			if digest != a.SHA256 {
				return "blocked", fmt.Errorf("artifact changed after inspection: %s", a.Name)
			}
		}
		fmt.Fprintln(s.out, "Artifact review complete. Confirm the installation transaction in pacman.")
		if err := pacmanInstallLocalWithMode(files, asDeps); err != nil {
			return "failed", fmt.Errorf("pacman transaction failed; pending evidence retained: %w", err)
		}
		for _, a := range artifacts {
			for _, file := range files {
				if pathsByName[a.Name] == file {
					installed.Versions[a.Name] = a.Version
				}
			}
		}
	}
	after, err := installedSnapshotFn()
	if err != nil {
		return "failed", fmt.Errorf("installation returned successfully but confirmation failed: %w", err)
	}
	for _, a := range artifacts {
		if after.Versions[a.Name] != a.Version {
			return "failed", fmt.Errorf("installed %s version does not match inspected artifact; baseline not advanced", a.Name)
		}
	}
	record.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.store.Save(record, false); err != nil {
		return "failed", fmt.Errorf("installed but could not save baseline: %w", err)
	}
	if err := s.store.ClearPending(base); err != nil {
		return "failed", err
	}
	_ = os.RemoveAll(buildDir)
	return "installed", nil
}

func (s *guidedSession) baseline(base string, installed pacman.Snapshot) *reviewstate.Record {
	if _, err := s.store.Load(base, true); err == nil {
		fmt.Fprintln(s.out, "Pending prior transaction found; full review is required to reconcile installation state.")
		return nil
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(s.out, "Pending evidence could not be read: %s. Full review required.\n", review.Safe(err.Error()))
		return nil
	}
	r, err := s.store.Load(base, false)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(s.out, "Saved baseline unavailable: %s\n", review.Safe(err.Error()))
		}
		return nil
	}
	for _, a := range r.Artifacts {
		if installed.Versions[a.Name] != a.Version {
			fmt.Fprintln(s.out, "Installed versions differ from saved evidence; full review required.")
			return nil
		}
	}
	return r
}
func auditRecipe(dir string, r *review.Report) error {
	u, err := sourceAuditFn(dir)
	if err != nil {
		return fmt.Errorf("source audit failed: %w", err)
	}
	if u.HasWarnings() {
		r.Add("source-audit", review.Review, "sources", formatSourceAuditFn(u))
	}
	h, err := shellAuditFn(dir)
	if err != nil {
		return fmt.Errorf("shell audit failed: %w", err)
	}
	if h.HasWarnings() {
		r.Add("shell-audit", review.Review, "shell", formatShellAuditFn(h))
	}
	return nil
}
func (s *guidedSession) approveRecipe(diff string, r review.Report) error {
	for {
		fmt.Fprint(s.out, "[A] Approve displayed recipe and findings, [D] redisplay diff, [S] skip, [Q] quit: ")
		a, err := review.Answer(s.in)
		if err != nil {
			return err
		}
		switch a {
		case "a":
			return nil
		case "d":
			printRecipeDiff(s.out, diff)
			r.Print(s.out)
		case "s":
			return errSkipped
		case "q":
			return errQuit
		}
	}
}
func guidedLint(target string, artifact bool) review.Report {
	var r review.Report
	tools := []string{"shellcheck", "namcap"}
	if artifact {
		tools = []string{"namcap"}
	}
	for _, name := range tools {
		if _, err := exec.LookPath(name); err != nil {
			r.Add("tool-unavailable", review.Review, name, "automatic check unavailable: "+err.Error())
			continue
		}
		file := target
		if !artifact {
			file = filepath.Join(target, "PKGBUILD")
		}
		if name == "shellcheck" {
			diagnostics, err := shellutil.ShellcheckDiagnostics(file)
			if err != nil {
				r.Add("tool-failed", review.Block, name, err.Error())
				continue
			}
			for _, d := range diagnostics {
				r.Add("shellcheck", review.Review, fmt.Sprintf("PKGBUILD:%d:%d", d.Line, d.Column), fmt.Sprintf("SC%d %s: %s", d.Code, d.Level, d.Message))
			}
			if len(diagnostics) == 0 {
				r.Add("tool-complete", review.Info, name, "check completed without diagnostics")
			}
			continue
		}
		out, err := shellutil.NamcapDiagnostics(file)
		if out != "" {
			r.Add("tool-diagnostics", review.Review, name, out)
		}
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 && (strings.Contains(out, " W: ") || strings.Contains(out, " E: ")) {
				continue
			}
			r.Add("tool-failed", review.Block, name, err.Error())
		} else if out == "" {
			r.Add("tool-complete", review.Info, name, "check completed without diagnostics")
		}
	}
	return r
}

func (s *guidedSession) inspect(base string, pkgs []aur.Package, buildDir, stage string, baseline *reviewstate.Record, effective reviewstate.Snapshot) ([]tarcheck.Manifest, map[string]string, []review.Finding, error) {
	entries, err := os.ReadDir(buildDir)
	if err != nil {
		return nil, nil, nil, err
	}
	expected := map[string]bool{}
	for _, p := range pkgs {
		expected[p.Name] = true
	}
	var manifests []tarcheck.Manifest
	pathsByName := map[string]string{}
	var report review.Report
	installed, err := installedSnapshotFn()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, e := range entries {
		if !tarcheck.IsArtifact(e.Name()) {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, nil, nil, fmt.Errorf("artifact is not regular: %s", e.Name())
		}
		src := filepath.Join(buildDir, e.Name())
		dst := filepath.Join(stage, e.Name())
		if err := copyPrivateArtifact(src, dst); err != nil {
			return nil, nil, nil, err
		}
		m, findings, err := inspectArtifactFn(dst)
		if err != nil {
			return nil, nil, nil, err
		}
		if !expected[m.Name] {
			fmt.Fprintf(s.out, "Leaving unrequested split output %s staged; it will not be installed.\n", review.Safe(m.Name))
			continue
		}
		if pathsByName[m.Name] != "" {
			return nil, nil, nil, fmt.Errorf("duplicate artifact for %s", m.Name)
		}
		if m.Base != "" && m.Base != base {
			return nil, nil, nil, fmt.Errorf("artifact package base mismatch")
		}
		if m.Arch != "any" && m.Arch != build.HostArchitecture() {
			return nil, nil, nil, fmt.Errorf("artifact architecture %s does not match this host", m.Arch)
		}
		if !(s.opt.Devel && developmentBase(pkgs)) {
			versions := recipeaudit.Fields(effective.Get(".SRCINFO"), "pkgver")
			releases := recipeaudit.Fields(effective.Get(".SRCINFO"), "pkgrel")
			epochs := recipeaudit.Fields(effective.Get(".SRCINFO"), "epoch")
			if len(versions) == 1 && len(releases) == 1 {
				want := versions[0] + "-" + releases[0]
				if len(epochs) == 1 && epochs[0] != "0" {
					want = epochs[0] + ":" + want
				}
				if m.Version != want {
					return nil, nil, nil, fmt.Errorf("artifact version %s differs from reviewed version %s", m.Version, want)
				}
			}
		}
		if version := installed.Versions[m.Name]; version != "" {
			cmp, err := guidedCompareFn(m.Version, version)
			if err != nil {
				return nil, nil, nil, err
			}
			if cmp < 0 || (cmp == 0 && !(s.opt.Devel && developmentBase(pkgs))) {
				return nil, nil, nil, fmt.Errorf("artifact %s %s is not an upgrade of %s", m.Name, m.Version, version)
			}
		}
		var old *tarcheck.Manifest
		if baseline != nil {
			for i := range baseline.Artifacts {
				if baseline.Artifacts[i].Name == m.Name {
					old = &baseline.Artifacts[i]
					break
				}
			}
		}
		comparison := tarcheck.Compare(m, old, installed.Files[m.Name], installed.Owners, os.Lstat)
		report.Findings = append(report.Findings, findings.Findings...)
		report.Findings = append(report.Findings, comparison.Findings...)
		lint := guidedLintFn(dst, true)
		report.Findings = append(report.Findings, lint.Findings...)
		fmt.Fprintf(s.out, "\nArtifact %s %s: %d entries, SHA-256 %s\n", review.Safe(m.Name), review.Safe(m.Version), len(m.Files), m.SHA256)
		pathsByName[m.Name] = dst
		manifests = append(manifests, m)
		if _, err := os.Lstat(src + ".sig"); err == nil {
			if err := copyPrivateArtifact(src+".sig", dst+".sig"); err != nil {
				return nil, nil, nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, nil, nil, err
		}
	}
	for name := range expected {
		if pathsByName[name] == "" {
			return nil, nil, nil, fmt.Errorf("missing expected artifact for %s", name)
		}
	}
	report.Print(s.out)
	if report.Has(review.Block) {
		return nil, nil, nil, fmt.Errorf("artifact checks block installation")
	}
	if report.Has(review.Review) {
		for {
			fmt.Fprint(s.out, "Artifact findings require review. [A] Accept findings, [F] files, [S] skip, [Q] quit: ")
			a, err := review.Answer(s.in)
			if err != nil {
				return nil, nil, nil, err
			}
			if a == "a" {
				break
			}
			if a == "s" || a == "skip" {
				return nil, nil, nil, errSkipped
			}
			if a == "q" || a == "quit" {
				return nil, nil, nil, errQuit
			}
			if a == "f" || a == "files" {
				for _, m := range manifests {
					for _, f := range m.Files {
						fmt.Fprintf(s.out, "%04o %s -> %s\n", f.Mode, review.Safe(f.Path), review.Safe(f.Link))
					}
				}
			}
		}
	}
	return manifests, pathsByName, report.Findings, nil
}
func copyPrivateArtifact(src, dst string) error {
	fd, err := unix.Open(src, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(fd), src)
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 32<<30 {
		return fmt.Errorf("artifact is not regular or exceeds size limit")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, (32<<30)+1))
	closeErr := out.Close()
	if n > 32<<30 {
		return fmt.Errorf("artifact exceeds size limit")
	}
	if err != nil {
		return err
	}
	return closeErr
}
