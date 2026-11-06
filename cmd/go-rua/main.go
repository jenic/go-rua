package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-rua/internal/aur"
	"go-rua/internal/build"
	install "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/review"
	"go-rua/internal/shellaudit"
	"go-rua/internal/shellutil"
	"go-rua/internal/sourceaudit"
	"go-rua/internal/tarcheck"
	"go-rua/internal/term"
	"go-rua/internal/upstream"
)

var Version string

// test seams for dependency injection
var (
	aurInfoFn               = aur.Info
	aurSearchANDFn          = aur.SearchAND
	installPlanFn           = install.BuildPlan
	installInstallFn        = install.Install
	summarizeAURFn          = install.SummarizeForAUR
	formatSummaryFn         = install.FormatSummary
	pacmanSudoFn            = pacman.SudoCommand
	pacmanInstallRepoDepsFn = pacman.InstallRepoDeps
	getForeignPkgsFn        = pacman.GetForeignPackages
	vercmpFn                = pacman.Vercmp
	getIgnoredPkgsFn        = pacman.GetIgnoredPackages
	tarcheckFn              = tarcheck.TarCheck
	shellcheckFn            = shellutil.Shellcheck
	namcapFn                = shellutil.Namcap
	pathsInitFn             = paths.MustInit
	pathsInitNoMakepkgFn    = paths.MustInitNoMakepkgChecks
	buildDirectoryCLIFn     = build.BuildDirectory
	sourceAuditDirFn        = sourceaudit.AuditDir
	formatSourceAuditFn     = sourceaudit.FormatReport
	shellAuditDirFn         = shellaudit.AuditDir
	formatShellAuditFn      = shellaudit.FormatReport
	upstreamCheckFn         = func(ctx context.Context, requests []upstream.Request) []upstream.Report {
		return upstream.DefaultChecker(vercmpFn).Check(ctx, requests)
	}
	upstreamPlanFn = func(ctx context.Context, request upstream.Request, candidate upstream.Candidate) (upstream.Plan, error) {
		recipe, err := upstream.FetchAURFile(ctx, nil, "", request.PackageBase, "PKGBUILD")
		if err != nil {
			return upstream.Plan{}, err
		}
		return upstream.PlanOverride(recipe, upstream.ApplyRequest{PackageBase: request.PackageBase, AURVersion: request.AURVersion, Candidate: candidate}, upstream.HostArchitecture())
	}
	upstreamPlanAllFn = func(ctx context.Context, request upstream.Request, candidate upstream.Candidate) (upstream.Plan, error) {
		recipe, err := upstream.FetchAURFile(ctx, nil, "", request.PackageBase, "PKGBUILD")
		if err != nil {
			return upstream.Plan{}, err
		}
		return upstream.PlanOverrideForArchitectures(recipe, upstream.ApplyRequest{PackageBase: request.PackageBase, AURVersion: request.AURVersion, Candidate: candidate}, upstream.HostArchitecture(), true)
	}
	upstreamApplyFn       = upstream.ApplyBuildCopy
	upstreamPolicyFatalFn = func(err error) { fatalf("%v", err) }
)

func usage() {
	printGlobalHelp(os.Stdout)
}

func main() {
	// Global color flag: --color=always|never|auto (set RUA_COLOR env and strip from args)
	if len(os.Args) > 1 {
		filtered := []string{}
		skipNext := false
		for i := 0; i < len(os.Args); i++ {
			if skipNext {
				skipNext = false
				continue
			}
			a := os.Args[i]
			if strings.HasPrefix(a, "--color=") {
				if err := setColorMode(strings.TrimPrefix(a, "--color=")); err != nil {
					fmt.Fprintln(os.Stderr, "Error:", err)
					os.Exit(2)
				}
				continue
			}
			if a == "--color" {
				if i+1 >= len(os.Args) {
					fmt.Fprintln(os.Stderr, "Error: --color requires a value: always, never, or auto")
					os.Exit(2)
				}
				if err := setColorMode(os.Args[i+1]); err != nil {
					fmt.Fprintln(os.Stderr, "Error:", err)
					os.Exit(2)
				}
				skipNext = true
				continue
			}
			filtered = append(filtered, a)
		}
		os.Args = filtered
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "sandbox-exec":
		// hidden internal entrypoint for sandbox runner
		sandboxExec()
		return
	case "version", "--version", "-v":
		versionCmd(os.Args[2:])
	case "builddir":
		builddirCmd(os.Args[2:])
	case "shellcheck":
		shellcheckCmd(os.Args[2:])
	case "namcap":
		namcapCmd(os.Args[2:])
	case "install":
		installCmd(os.Args[2:])
	case "search":
		searchCmd(os.Args[2:])
	case "info":
		infoCmd(os.Args[2:])
	case "tarcheck":
		tarcheckCmd(os.Args[2:])
	case "upgrade":
		upgradeCmd(os.Args[2:])
	case "upstream":
		upstreamCmd(os.Args[2:])
	case "help", "-h", "--help":
		helpCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func setColorMode(value string) error {
	mode := strings.ToLower(strings.TrimSpace(value))
	switch mode {
	case "always", "never", "auto":
	default:
		return fmt.Errorf("invalid --color value %q: expected always, never, or auto", value)
	}
	if err := os.Setenv("RUA_COLOR", mode); err != nil {
		return fmt.Errorf("set color mode: %w", err)
	}
	term.Recompute()
	return nil
}

func helpCmd(args []string) {
	if len(args) == 0 {
		usage()
		return
	}
	switch args[0] {
	case "builddir":
		builddirCmd([]string{"--help"})
	case "shellcheck":
		shellcheckCmd([]string{"--help"})
	case "namcap":
		namcapCmd([]string{"--help"})
	case "install":
		installCmd([]string{"--help"})
	case "search":
		searchCmd([]string{"--help"})
	case "info":
		infoCmd([]string{"--help"})
	case "tarcheck":
		tarcheckCmd([]string{"--help"})
	case "upgrade":
		upgradeCmd([]string{"--help"})
	case "upstream":
		upstreamCmd([]string{"--help"})
	case "version":
		versionCmd([]string{"--help"})
	default:
		fmt.Fprintf(os.Stderr, "unknown help topic: %s\n\n", args[0])
		usage()
	}
}

func versionCmd(args []string) {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	setCommandUsage(fs, versionHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	fmt.Println(Version)
}

func builddirCmd(args []string) {
	fs := flag.NewFlagSet("builddir", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	offline := fs.Bool("offline", true, "Forbid internet access while building")
	online := fs.Bool("online", false, "Allow internet access while building; overrides --offline")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	forceBwrap := fs.Bool("bwrap", false, "Force bubblewrap isolation even when not offline")
	setCommandUsage(fs, builddirHelp)
	if !parseCommandFlags(fs, args) {
		return
	}

	dir := "."
	if fs.NArg() >= 1 {
		dir = fs.Arg(0)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fatalf("failed to resolve path: %v", err)
	}

	p := pathsInitFn()
	if *forceBwrap {
		_ = os.Setenv("RUA_ALWAYS_BWRAP", "1")
	}
	if report, err := sourceAuditDirFn(abs); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: source URL audit failed: %v\n", err)
	} else if report.HasWarnings() {
		fmt.Fprint(os.Stderr, formatSourceAuditFn(report))
	}
	if report, err := shellAuditDirFn(abs); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: shell logic audit failed: %v\n", err)
	} else if report.HasWarnings() {
		fmt.Fprint(os.Stderr, formatShellAuditFn(report))
	}
	effOffline := *offline && !*online
	if err := buildDirectoryCLIFn(abs, p, effOffline, *force, !*noSeccomp); err != nil {
		fatalf("build failed: %v", err)
	}
}

func shellcheckCmd(args []string) {
	fs := flag.NewFlagSet("shellcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	setCommandUsage(fs, shellcheckHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	var target string
	if fs.NArg() == 0 {
		target = "/dev/stdin"
	} else {
		target = fs.Arg(0)
	}

	// If it's a directory, append PKGBUILD
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		target = filepath.Join(target, "PKGBUILD")
	}

	if _, err := os.Stat(target); err != nil {
		fatalf("cannot access %s: %v", target, err)
	}

	p := pathsInitNoMakepkgFn()
	if err := shellcheckFn(target, p); err != nil {
		if err != nil {
			fatalf("shellcheck failed: %v", err)
		}
	}
}

func namcapCmd(args []string) {
	fs := flag.NewFlagSet("namcap", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	setCommandUsage(fs, namcapHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	var target string
	if fs.NArg() == 0 {
		target = "."
	} else {
		target = fs.Arg(0)
	}
	p := pathsInitNoMakepkgFn()
	if err := namcapFn(target, p); err != nil {
		fatalf("namcap failed: %v", err)
	}
}

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	offline := fs.Bool("offline", true, "Forbid internet access while building")
	online := fs.Bool("online", false, "Allow internet access while building; overrides --offline")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	asdeps := fs.Bool("asdeps", false, "Install built packages as dependencies")
	planOnly := fs.Bool("plan", false, "Print build plan and exit")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	stageOnly := fs.Bool("stage-only", false, "Stage built artifacts without installing them")
	setCommandUsage(fs, installHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	pkgs := fs.Args()
	if len(pkgs) == 0 {
		fs.Usage()
		return
	}
	p := pathsInitFn()
	if err := buildDepsNote(); err != nil { /* ignore */
	}
	if *planOnly {
		infos, err := aurInfoFn(pkgs)
		if err != nil {
			fatalf("failed to fetch AUR info: %v", err)
		}
		sum, err := summarizeAURFn(pkgs, infos)
		if err == nil {
			fmt.Print(formatSummaryFn(sum))
		}
		plan, err := installPlanFn(pkgs)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		fmt.Println(term.Bold("Plan:"))
		if len(plan.BuildOrder) == 0 {
			fmt.Println("  (no AUR builds needed)")
		} else {
			fmt.Printf("  Build order: %s\n", strings.Join(plan.BuildOrder, ", "))
		}
		if len(plan.RepoMissing) > 0 {
			fmt.Printf("  %s %s\n", term.Yellow("Repo deps missing:"), strings.Join(plan.RepoMissing, ", "))
			fmt.Printf("    Install: %s pacman -S --needed %s\n", pacmanSudoFn(), strings.Join(plan.RepoMissing, " "))
		} else {
			fmt.Println("  Repo deps missing: none")
		}
		if len(plan.Unknown) > 0 {
			fmt.Printf("  Unknown deps: %s\n", strings.Join(plan.Unknown, ", "))
		}
		return
	}
	// Print a pacman dependency summary before interactive steps
	if infos, err := aurInfoFn(pkgs); err == nil {
		if sum, err := summarizeAURFn(pkgs, infos); err == nil {
			fmt.Print(formatSummaryFn(sum))
		}
	}
	// Optionally install missing repo deps
	if *installRepoDeps {
		plan, err := installPlanFn(pkgs)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		if len(plan.RepoMissing) > 0 {
			fmt.Printf("Installing missing repo deps: %s\n", strings.Join(plan.RepoMissing, ", "))
			if err := pacmanInstallRepoDepsFn(plan.RepoMissing); err != nil {
				fatalf("pacman install failed: %v", err)
			}
		}
	}
	effOffline := *offline && !*online
	if err := (func() error {
		return installInstallFn(pkgs, p, install.Options{Offline: effOffline, Force: *force, InstallBuilt: !*stageOnly, DisableSeccomp: *noSeccomp, AsDeps: *asdeps})
	})(); err != nil {
		fatalf("install failed: %v", err)
	}
}

func searchCmd(args []string) {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	setCommandUsage(fs, searchHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return
	}
	results, err := aurSearchANDFn(fs.Args())
	if err != nil {
		fatalf("search failed: %v", err)
	}
	color := term.EnabledFor(os.Stdout)
	for _, p := range results {
		name, version := p.Name, p.Version
		if color {
			name, version = term.Cyan(name), term.Green(version)
		}
		fmt.Printf("%s %s - %s\n", name, version, strings.TrimSpace(p.Description))
	}
}

func infoCmd(args []string) {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	jsonOut := fs.Bool("json", false, "Output JSON")
	setCommandUsage(fs, infoHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return
	}
	info, err := aurInfoFn(fs.Args())
	if err != nil {
		fatalf("info failed: %v", err)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			fatalf("encode failed: %v", err)
		}
		return
	}
	// pretty text output
	for _, p := range info {
		fmt.Printf("%s %s\n", p.Name, p.Version)
		if d := strings.TrimSpace(p.Description); d != "" {
			fmt.Printf("  desc: %s\n", d)
		}
		if p.URL != "" {
			fmt.Printf("  url:  %s\n", p.URL)
		}
		if p.Maintainer != "" {
			fmt.Printf("  maintainer: %s\n", p.Maintainer)
		}
		if p.NumVotes > 0 || p.Popularity > 0 {
			fmt.Printf("  votes: %d  pop: %.2f\n", p.NumVotes, p.Popularity)
		}
		if p.OutOfDate > 0 {
			fmt.Printf("  out-of-date: %d\n", p.OutOfDate)
		}
		if len(p.Depends) > 0 {
			fmt.Printf("  depends: %s\n", strings.Join(p.Depends, ", "))
		}
		if len(p.MakeDepends) > 0 {
			fmt.Printf("  makedepends: %s\n", strings.Join(p.MakeDepends, ", "))
		}
		if len(p.CheckDepends) > 0 {
			fmt.Printf("  checkdepends: %s\n", strings.Join(p.CheckDepends, ", "))
		}
		if len(p.OptDepends) > 0 {
			fmt.Printf("  optdepends: %s\n", strings.Join(p.OptDepends, ", "))
		}
		if len(p.Provides) > 0 {
			fmt.Printf("  provides: %s\n", strings.Join(p.Provides, ", "))
		}
		if len(p.Conflicts) > 0 {
			fmt.Printf("  conflicts: %s\n", strings.Join(p.Conflicts, ", "))
		}
		fmt.Println()
	}
}

func tarcheckCmd(args []string) {
	fs := flag.NewFlagSet("tarcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	setCommandUsage(fs, tarcheckHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return
	}
	target := fs.Arg(0)
	if _, err := os.Stat(target); err != nil {
		fatalf("cannot access %s: %v", target, err)
	}
	if err := tarcheckFn(target); err != nil {
		fatalf("tarcheck failed: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Finished checking package: %s\n", target)
}

func upgradeCmd(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	printOnly := fs.Bool("printonly", false, "Print outdated packages and exit")
	plan := fs.Bool("plan", false, "Print upgrade plan and exit")
	devel := fs.Bool("devel", false, "Also rebuild development VCS packages (-git, -hg, -bzr, -svn, -cvs, -darcs)")
	ignore := fs.String("ignore", "", "Comma-separated list of packages to ignore")
	offline := fs.Bool("offline", true, "Forbid internet access while building")
	online := fs.Bool("online", false, "Allow internet access while building; overrides --offline")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	noUpstreamCheck := fs.Bool("no-upstream-check", false, "Disable best-effort upstream release and tag checks in --plan")
	useUpstream := fs.Bool("upstream", false, "Opt in to eligible verified GitHub upstream overrides")
	validateAllArches := fs.Bool("validate-all-arches", false, "Verify and rewrite every declared architecture (requires --upstream)")
	setCommandUsage(fs, upgradeHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	if *useUpstream && *noUpstreamCheck {
		fatalf("--upstream cannot be combined with --no-upstream-check")
	}
	if *validateAllArches && !*useUpstream {
		fatalf("--validate-all-arches requires --upstream")
	}
	outdated, nonexistent, err := findOutdated(*devel, *ignore)
	if err != nil {
		fatalf("upgrade check failed: %v", err)
	}
	if *printOnly {
		if len(outdated) == 0 && len(nonexistent) == 0 {
			os.Exit(7)
		}
		for _, n := range outdated {
			fmt.Println(n)
		}
		for _, n := range nonexistent {
			fmt.Println(n)
		}
		return
	}
	var reports []upstream.Report
	requestsByName := map[string]upstream.Request{}
	eligible := map[string]upstream.ApplyRequest{}
	eligibilityPlans := map[string]upstream.Plan{}
	ineligibleReasons := map[string]string{}
	if (*plan && !*noUpstreamCheck) || *useUpstream {
		requests, requestErr := collectUpstreamRequests(*ignore)
		if requestErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: upstream discovery unavailable: %v\n", requestErr)
		} else if len(requests) > 0 {
			for _, request := range requests {
				requestsByName[request.Name] = request
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			reports = upstreamCheckFn(ctx, requests)
			if *useUpstream {
				if err := upstreamPolicyApplicationError(reports); err != nil {
					cancel()
					upstreamPolicyFatalFn(err)
					return
				}
			}
			for _, report := range reports {
				if !*useUpstream || report.Candidate == nil || !report.Candidate.NewerThanLocal || !report.Candidate.NewerThanAUR {
					continue
				}
				request, ok := requestsByName[report.Package]
				if !ok {
					continue
				}
				planFunction := upstreamPlanFn
				if *validateAllArches {
					planFunction = upstreamPlanAllFn
				}
				overridePlan, planErr := planFunction(ctx, request, *report.Candidate)
				if planErr != nil {
					ineligibleReasons[report.Package] = planErr.Error()
					fmt.Fprintf(os.Stderr, "Warning: %s upstream candidate is ineligible: %v\n", report.Package, planErr)
					continue
				}
				eligible[report.Package] = upstream.ApplyRequest{Name: request.Name, LocalVersion: request.LocalVersion, PackageBase: request.PackageBase, AURVersion: request.AURVersion, Candidate: *report.Candidate}
				eligibilityPlans[report.Package] = overridePlan
			}
			cancel()
		}
	}
	if len(outdated) == 0 && len(nonexistent) == 0 && len(eligible) == 0 {
		if *plan && !*noUpstreamCheck {
			printUpstreamReports(reports)
		}
		osExitFn(7)
		return
	}
	if *plan {
		// Detailed outdated table
		items, _, _ := listOutdatedDetailed(*devel, *ignore)
		if len(items) > 0 {
			fmt.Println(term.Bold("Outdated AUR packages:"))
			for _, it := range items {
				fmt.Printf("  %s  %s -> %s\n", it.Name, it.Local, it.Latest)
			}
		}
		if !*noUpstreamCheck {
			printUpstreamReports(reports)
		}
		if *useUpstream && len(eligibilityPlans) > 0 {
			fmt.Println(term.Bold("Eligible upstream overrides:"))
			var names []string
			for name := range eligibilityPlans {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				overridePlan := eligibilityPlans[name]
				fmt.Printf("  %s: pkgver %s -> %s; pkgrel -> 1\n", name, overridePlan.FromVersion, overridePlan.ToVersion)
				for _, mapping := range overridePlan.Mappings {
					if mapping.Kind == "git" {
						fmt.Printf("    %s[%d] -> immutable Git commit %s; %s[%d] remains SKIP\n", mapping.SourceKey, mapping.Index, mapping.GitReference.CommitSHA, mapping.ChecksumKey, mapping.Index)
					} else {
						fmt.Printf("    %s[%d] -> %s; %s[%d] -> downloaded SHA-256\n", mapping.SourceKey, mapping.Index, mapping.Asset.Name, mapping.ChecksumKey, mapping.Index)
					}
				}
			}
		}
		if *useUpstream && len(ineligibleReasons) > 0 {
			fmt.Println(term.Bold("Ineligible upstream candidates:"))
			var names []string
			for name := range ineligibleReasons {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fmt.Printf("  %s: %s\n", name, ineligibleReasons[name])
			}
		}
		targets := mergeUpgradeTargets(outdated, eligible)
		pl, err := installPlanFn(targets)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		fmt.Println(term.Bold("Plan:"))
		if len(pl.BuildOrder) == 0 {
			fmt.Println("  (no AUR builds needed)")
		} else {
			fmt.Printf("  Build order: %s\n", strings.Join(pl.BuildOrder, ", "))
		}
		if len(pl.RepoMissing) > 0 {
			fmt.Printf("  %s %s\n", term.Yellow("Repo deps missing:"), strings.Join(pl.RepoMissing, ", "))
			fmt.Printf("    Install: %s pacman -S --needed %s\n", pacmanSudoFn(), strings.Join(pl.RepoMissing, " "))
		} else {
			fmt.Println("  Repo deps missing: none")
		}
		if len(pl.Unknown) > 0 {
			fmt.Printf("  Unknown deps: %s\n", strings.Join(pl.Unknown, ", "))
		}
		printNonexistentPackages(nonexistent)
		return
	}
	printNonexistentPackages(nonexistent)
	targets := mergeUpgradeTargets(outdated, eligible)
	if len(targets) == 0 {
		return
	}
	if *useUpstream {
		fmt.Fprintln(os.Stderr, "Warning: --upstream is an explicit trust decision that builds a GitHub release or immutable Git tag target newer than the reviewed AUR recipe. Review the generated diff and verification evidence before approving it.")
	}
	// Build and install in order by default.
	pl, err := installPlanFn(targets)
	if err != nil {
		fatalf("plan failed: %v", err)
	}
	if *installRepoDeps && len(pl.RepoMissing) > 0 {
		fmt.Printf("Installing missing repo deps: %s\n", strings.Join(pl.RepoMissing, ", "))
		if err := pacmanInstallRepoDepsFn(pl.RepoMissing); err != nil {
			fatalf("pacman install failed: %v", err)
		}
	}
	p := pathsInitFn()
	installOptions := install.Options{Guided: true, Plan: &pl, Devel: *devel, Offline: *offline && !*online, Force: *force, InstallBuilt: true, DisableSeccomp: *noSeccomp}
	if len(eligible) > 0 {
		installOptions.UpstreamBases = map[string]bool{}
		hooks := map[string]func(string, string, string) error{}
		for _, name := range targets {
			if request, ok := eligible[name]; ok {
				installOptions.UpstreamBases[request.PackageBase] = true
				if _, exists := hooks[request.PackageBase]; !exists {
					hooks[request.PackageBase] = upstreamPrepareHookForArchitectures(request, p, *validateAllArches)
				}
			}
		}
		installOptions.PrepareBuildCopy = func(base, reviewDir, buildDir string) error {
			if hook := hooks[base]; hook != nil {
				return hook(base, reviewDir, buildDir)
			}
			return nil
		}
	}
	if err := installInstallFn(targets, p, installOptions); err != nil {
		fatalf("upgrade failed: %v", err)
	}
}

func upstreamPolicyApplicationError(reports []upstream.Report) error {
	for _, report := range reports {
		if report.PolicyReason != "" {
			return fmt.Errorf("%s upstream policy is invalid: %s", report.Package, report.PolicyReason)
		}
	}
	return nil
}

func mergeUpgradeTargets(outdated []string, eligible map[string]upstream.ApplyRequest) []string {
	seen := map[string]bool{}
	result := append([]string(nil), outdated...)
	for _, name := range result {
		seen[name] = true
	}
	var additions []string
	for name := range eligible {
		if !seen[name] {
			additions = append(additions, name)
		}
	}
	sort.Strings(additions)
	return append(result, additions...)
}

func upstreamPrepareHook(request upstream.ApplyRequest, p paths.Paths) func(string, string, string) error {
	return upstreamPrepareHookForArchitectures(request, p, false)
}

func upstreamPrepareHookForArchitectures(request upstream.ApplyRequest, p paths.Paths, validateAllArches bool) func(string, string, string) error {
	return func(pkgbase, reviewDir, buildDir string) error {
		if pkgbase != request.PackageBase {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		installedVersion, err := currentForeignVersion(request.Name)
		if err != nil {
			return fmt.Errorf("re-read installed package version: %w", err)
		}
		if installedVersion != request.LocalVersion {
			return fmt.Errorf("installed %s version changed after planning: got %s want %s", request.Name, installedVersion, request.LocalVersion)
		}
		compare, err := vercmpFn(installedVersion, request.Candidate.FullVersion)
		if err != nil {
			return fmt.Errorf("compare fresh installed version to upstream candidate: %w", err)
		}
		if compare >= 0 {
			return fmt.Errorf("upstream candidate %s is no longer newer than installed %s", request.Candidate.FullVersion, installedVersion)
		}
		_, err = upstreamApplyFn(ctx, reviewDir, buildDir, request, upstream.ApplyOptions{
			Verifier:          upstream.GPGVerifier{},
			EvidenceDir:       filepath.Join(filepath.Dir(p.DataCheckedTars), "upstream_evidence"),
			ValidateAllArches: validateAllArches,
			Revalidate: func(ctx context.Context, planned upstream.ApplyRequest) (upstream.Candidate, error) {
				reports := upstreamCheckFn(ctx, []upstream.Request{{Name: planned.Name, PackageBase: planned.PackageBase, LocalVersion: planned.LocalVersion, AURVersion: planned.AURVersion}})
				if len(reports) != 1 || reports[0].Candidate == nil || reports[0].UnknownReason != "" {
					return upstream.Candidate{}, fmt.Errorf("candidate is no longer available")
				}
				return *reports[0].Candidate, nil
			},
			Audit: func(dir string) error {
				sourceReport, err := sourceAuditDirFn(dir)
				if err != nil {
					return err
				}
				if sourceReport.HasWarnings() {
					return fmt.Errorf("source audit warnings remain:\n%s", formatSourceAuditFn(sourceReport))
				}
				shellReport, err := shellAuditDirFn(dir)
				if err != nil {
					return err
				}
				if shellReport.HasWarnings() {
					return fmt.Errorf("shell audit warnings remain:\n%s", formatShellAuditFn(shellReport))
				}
				return nil
			},
			Confirm: func(diff string, evidence upstream.Evidence) (bool, error) {
				fmt.Println(term.Bold("Upstream override diff:"))
				fmt.Println(diff)
				if evidence.ReleaseID > 0 {
					fmt.Printf("Verified GitHub %s tag %s, release %d.\n", evidence.Repository, evidence.Tag, evidence.ReleaseID)
				} else {
					fmt.Printf("Verified GitHub %s tag %s.\n", evidence.Repository, evidence.Tag)
				}
				fmt.Printf("  Host %s; recipe %s -> %s\n", evidence.HostArchitecture, evidence.BaselineRecipeSHA256, evidence.GeneratedRecipeSHA256)
				for _, artifact := range evidence.Artifacts {
					fmt.Printf("  Artifact %s (id %d, size %d): SHA-256 %s via %s", artifact.Name, artifact.ID, artifact.Size, artifact.SHA256, strings.Join(artifact.Methods, ", "))
					if len(artifact.Signers) > 0 {
						fmt.Printf("; signer(s) %s", strings.Join(artifact.Signers, ", "))
					}
					fmt.Println()
					for _, sidecar := range artifact.Sidecars {
						fmt.Printf("    Sidecar %s (id %d, size %d): SHA-256 %s\n", sidecar.Kind, sidecar.ID, sidecar.Size, sidecar.LocalSHA256)
					}
				}
				for _, reference := range evidence.GitReferences {
					fmt.Printf("  Git %s[%d] (%s): tag object %s -> commit %s", reference.SourceKey, reference.SourceIndex, reference.Architecture, reference.RefSHA, reference.CommitSHA)
					if reference.SignatureVerified {
						fmt.Printf("; anchored signer %s", reference.Signer)
					} else {
						fmt.Print("; unsigned GitHub ref identity")
					}
					fmt.Println()
				}
				fmt.Print("Apply this override to the ephemeral build copy? [y/N]: ")
				answer, err := review.Answer(os.Stdin)
				return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes"), err
			},
		})
		return err
	}
}

func upstreamCmd(args []string) {
	fs := flag.NewFlagSet("upstream", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	jsonOutput := fs.Bool("json", false, "Emit machine-readable JSON")
	exportDir := fs.String("export-evidence", "", "Atomically export validated evidence to a new directory")
	gcEvidence := fs.Bool("gc-evidence", false, "Remove abandoned temporary evidence files")
	setCommandUsage(fs, upstreamHelp)
	if !parseCommandFlags(fs, args) {
		return
	}
	if *exportDir != "" && *gcEvidence {
		fatalf("--export-evidence and --gc-evidence are mutually exclusive")
	}
	p := pathsInitNoMakepkgFn()
	evidenceDir := filepath.Join(filepath.Dir(p.DataCheckedTars), "upstream_evidence")
	if *exportDir != "" {
		if fs.NArg() != 0 {
			fatalf("--export-evidence does not accept package arguments")
		}
		result, err := upstream.ExportEvidence(evidenceDir, *exportDir)
		if err != nil {
			fatalf("export upstream evidence: %v", err)
		}
		printEvidenceOperation(result, *jsonOutput, "exported")
		return
	}
	if *gcEvidence {
		if fs.NArg() != 0 {
			fatalf("--gc-evidence does not accept package arguments")
		}
		result, err := upstream.GCEvidence(evidenceDir)
		if err != nil {
			fatalf("garbage collect upstream evidence: %v", err)
		}
		printEvidenceOperation(result, *jsonOutput, "retained")
		return
	}
	requests, err := collectUpstreamRequests("")
	if err != nil {
		fatalf("collect upstream status: %v", err)
	}
	if fs.NArg() > 0 {
		wanted := map[string]bool{}
		for _, name := range fs.Args() {
			wanted[name] = true
		}
		filtered := requests[:0]
		for _, request := range requests {
			if wanted[request.Name] || wanted[request.PackageBase] {
				filtered = append(filtered, request)
			}
		}
		requests = filtered
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reports := upstreamCheckFn(ctx, requests)
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(reports); err != nil {
			fatalf("encode upstream status: %v", err)
		}
		return
	}
	printUpstreamReports(reports)
}

func printEvidenceOperation(result upstream.EvidenceOperation, jsonOutput bool, verb string) {
	if jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fatalf("encode evidence result: %v", err)
		}
		return
	}
	fmt.Printf("Evidence %s: %d records, %d bytes", verb, result.Files, result.Bytes)
	if result.Removed > 0 {
		fmt.Printf("; removed %d abandoned temporary files", result.Removed)
	}
	fmt.Println()
}

func currentForeignVersion(name string) (string, error) {
	packages, err := getForeignPkgsFn()
	if err != nil {
		return "", err
	}
	version := ""
	for _, pkg := range packages {
		if pkg.Name != name {
			continue
		}
		if version != "" {
			return "", fmt.Errorf("pacman reported duplicate installed package %s", name)
		}
		version = pkg.Version
	}
	if version == "" {
		return "", fmt.Errorf("package %s is no longer installed as a foreign package", name)
	}
	return version, nil
}

func collectUpstreamRequests(ignoreCSV string) ([]upstream.Request, error) {
	foreign, err := getForeignPkgsFn()
	if err != nil {
		return nil, err
	}
	if len(foreign) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(foreign))
	for _, pkg := range foreign {
		names = append(names, pkg.Name)
	}
	infos, err := aurInfoFn(names)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]aur.Package, len(infos))
	for _, info := range infos {
		byName[info.Name] = info
	}
	ignored := parseIgnoredCSV(ignoreCSV)
	if systemIgnored, err := getIgnoredPkgsFn(); err == nil {
		for _, name := range systemIgnored {
			ignored[name] = struct{}{}
		}
	}
	requests := make([]upstream.Request, 0, len(infos))
	for _, pkg := range foreign {
		if _, skip := ignored[pkg.Name]; skip {
			continue
		}
		info, ok := byName[pkg.Name]
		if !ok || info.PackageBase == "" {
			continue
		}
		requests = append(requests, upstream.Request{
			Name: pkg.Name, PackageBase: info.PackageBase, LocalVersion: pkg.Version, AURVersion: info.Version,
		})
	}
	return requests, nil
}

func parseIgnoredCSV(value string) map[string]struct{} {
	ignored := map[string]struct{}{}
	for _, name := range strings.Split(value, ",") {
		if name = strings.TrimSpace(name); name != "" {
			ignored[name] = struct{}{}
		}
	}
	return ignored
}

func printUpstreamReports(reports []upstream.Report) {
	printedHeader := false
	for _, report := range reports {
		if report.Candidate == nil && report.UnknownReason == "" {
			continue
		}
		if !printedHeader {
			fmt.Println(term.Bold("Upstream status:"))
			printedHeader = true
		}
		fmt.Printf("  %s:\n", report.Package)
		if report.UnknownReason != "" {
			fmt.Printf("    Status: unknown (%s)\n", report.UnknownReason)
			continue
		}
		candidate := report.Candidate
		fmt.Printf("    Source: %s\n", report.Source)
		if candidate.Configured {
			fmt.Printf("    Policy: %s (host %s, API origin %s)\n", candidate.PolicyReason, candidate.Host, candidate.APIOrigin)
		}
		fmt.Printf("    Installed: %s\n", report.LocalVersion)
		fmt.Printf("    AUR: %s\n", report.AURVersion)
		fmt.Printf("    GitHub: %s (tag %s, confidence %s)\n", candidate.FullVersion, candidate.Tag, candidate.Confidence)
		switch {
		case candidate.NewerThanLocal:
			fmt.Println("    Local status: upstream is newer than installed")
		case report.LocalCompare == 0:
			fmt.Println("    Local status: installed matches upstream")
		default:
			fmt.Println("    Local status: installed is newer than detected upstream")
		}
		if candidate.NewerThanAUR {
			fmt.Printf("    AUR lag: yes (%s -> %s)\n", report.AURVersion, candidate.FullVersion)
		} else {
			fmt.Println("    AUR lag: no")
		}
		for _, reason := range candidate.Reasons {
			fmt.Printf("    Reason: %s\n", reason)
		}
		for _, asset := range candidate.Assets {
			sidecars := detectedSidecars(asset.Sidecars)
			fmt.Printf("    Asset [%s]: %s (detected sidecars: %s)\n", asset.Architecture, asset.Name, strings.Join(sidecars, ", "))
		}
		for _, reference := range candidate.GitReferences {
			signature := "not requested"
			if reference.SignatureRequired {
				signature = "required by PKGBUILD"
			} else if reference.SignaturePresent {
				signature = "published; verified during apply when anchored"
			}
			fmt.Printf("    Git [%s] %s[%d]: tag object %s -> commit %s (signature %s)\n", reference.Architecture, reference.SourceKey, reference.SourceIndex, reference.RefSHA, reference.CommitSHA, signature)
		}
	}
}

func detectedSidecars(sidecars upstream.Sidecars) []string {
	var result []string
	if sidecars.SHA256 {
		result = append(result, ".sha256")
	}
	if sidecars.Signature {
		result = append(result, ".asc")
	}
	if sidecars.SHA256Signed {
		label := ".sha256.asc"
		if !sidecars.SHA256 {
			label += " (incomplete chain: .sha256 missing)"
		}
		result = append(result, label)
	}
	if len(result) == 0 {
		return []string{"none detected"}
	}
	return result
}

func printNonexistentPackages(names []string) {
	if len(names) > 0 {
		fmt.Printf("  Note: %d installed packages not found in AUR: %s\n", len(names), strings.Join(names, ", "))
	}
}

func parseCommandFlags(fs *flag.FlagSet, args []string) bool {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false
		}
		os.Exit(2)
		return false
	}
	return true
}

func fatalf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, "Error:", msg)
	os.Exit(1)
}

// buildDepsNote prints a minimal hint about pacman dependencies for build
func buildDepsNote() error {
	fmt.Println("Note: pacman dependencies must be installed outside the sandbox.")
	fmt.Println("Make sure base-devel and package-specific deps are installed.")
	return nil
}

// findOutdated returns names of foreign packages that have newer AUR versions
func findOutdated(devel bool, ignoreCSV string) ([]string, []string, error) {
	foreign, err := getForeignPkgsFn()
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(foreign))
	for _, f := range foreign {
		names = append(names, f.Name)
	}
	if len(names) == 0 {
		return nil, nil, nil
	}
	infos, err := aurInfoFn(names)
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]string{}
	for _, inf := range infos {
		byName[inf.Name] = inf.Version
	}
	// ignored from CLI and pacman-conf
	ignoreSet := map[string]struct{}{}
	if ignoreCSV != "" {
		for _, s := range strings.Split(ignoreCSV, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				ignoreSet[s] = struct{}{}
			}
		}
	}
	if sysIg, err := getIgnoredPkgsFn(); err == nil {
		for _, s := range sysIg {
			ignoreSet[s] = struct{}{}
		}
	}
	var outdated []string
	var nonexistent []string
	for _, f := range foreign {
		if _, ig := ignoreSet[f.Name]; ig {
			continue
		}
		latest := byName[f.Name]
		if latest == "" {
			// not found in AUR
			nonexistent = append(nonexistent, f.Name)
			continue
		}
		// consider VCS packages when --devel
		if devel && isDevelPkg(f.Name) {
			outdated = append(outdated, f.Name)
			continue
		}
		cmp, err := vercmpFn(f.Version, latest)
		if err != nil {
			continue
		}
		if cmp < 0 {
			outdated = append(outdated, f.Name)
		}
	}
	return outdated, nonexistent, nil
}

func isDevelPkg(name string) bool {
	// matches -git, -hg, -bzr, -svn, -cvs, -darcs optionally with additional suffixes
	for _, suf := range []string{"-git", "-hg", "-bzr", "-svn", "-cvs", "-darcs"} {
		if strings.Contains(name, suf) {
			return true
		}
	}
	return false
}

type OutdatedItem struct {
	Name   string
	Local  string
	Latest string
}

func listOutdatedDetailed(devel bool, ignoreCSV string) ([]OutdatedItem, []string, error) {
	foreign, err := getForeignPkgsFn()
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(foreign))
	for _, f := range foreign {
		names = append(names, f.Name)
	}
	if len(names) == 0 {
		return nil, nil, nil
	}
	infos, err := aurInfoFn(names)
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]string{}
	for _, inf := range infos {
		byName[inf.Name] = inf.Version
	}
	ignoreSet := map[string]struct{}{}
	if ignoreCSV != "" {
		for _, s := range strings.Split(ignoreCSV, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				ignoreSet[s] = struct{}{}
			}
		}
	}
	if sysIg, err := getIgnoredPkgsFn(); err == nil {
		for _, s := range sysIg {
			ignoreSet[s] = struct{}{}
		}
	}
	var items []OutdatedItem
	var nonexistent []string
	for _, f := range foreign {
		if _, ig := ignoreSet[f.Name]; ig {
			continue
		}
		latest := byName[f.Name]
		if latest == "" {
			nonexistent = append(nonexistent, f.Name)
			continue
		}
		if devel && isDevelPkg(f.Name) {
			items = append(items, OutdatedItem{Name: f.Name, Local: f.Version, Latest: latest})
			continue
		}
		cmp, err := vercmpFn(f.Version, latest)
		if err == nil && cmp < 0 {
			items = append(items, OutdatedItem{Name: f.Name, Local: f.Version, Latest: latest})
		}
	}
	return items, nonexistent, nil
}
