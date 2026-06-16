package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go-rua/internal/aur"
	"go-rua/internal/build"
	install "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/shellaudit"
	"go-rua/internal/shellutil"
	"go-rua/internal/sourceaudit"
	"go-rua/internal/tarcheck"
	"go-rua/internal/term"
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
)

func usage() {
	fmt.Println("go-rua: AUR helper (Go), sandboxed by Landlock")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go-rua [command] [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  builddir [--online] [--force] [dir]     Build a PKGBUILD directory in sandbox (offline by default)")
	fmt.Println("  shellcheck [file|dir]                   Run shellcheck for PKGBUILD (sandboxed)")
	fmt.Println("  namcap [file|dir]                       Run namcap for PKGBUILD (sandboxed)")
	fmt.Println("  install [--online] [--force] [--install] [--asdeps] [--plan] <pkgs..>  Clone AUR repos, review, build, stage, optional install")
	fmt.Println("  search <keywords...>                    Search AUR by name/desc")
	fmt.Println("  info <pkg1> [pkg2 ...]                  Show AUR package info")
	fmt.Println("  tarcheck <archive>                      Inspect built package archive (interactive)")
	fmt.Println("  upgrade [--apply] [--devel] [--ignore=<pkg1,pkg2>]  Plan upgrades by default; --apply builds and installs")
	fmt.Println("  version                                 Show version")
	fmt.Println()
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
				os.Setenv("RUA_COLOR", strings.TrimPrefix(a, "--color="))
				continue
			}
			if a == "--color" && i+1 < len(os.Args) {
				os.Setenv("RUA_COLOR", os.Args[i+1])
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
		fmt.Println(Version)
		return
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
	case "help", "-h", "--help":
		helpCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func helpCmd(args []string) {
	if len(args) == 0 {
		usage()
		return
	}
	switch args[0] {
	case "builddir":
		builddirUsage()
	case "shellcheck":
		shellcheckUsage()
	case "namcap":
		namcapUsage()
	case "install":
		installUsage()
	case "search":
		searchUsage()
	case "info":
		infoUsage()
	case "tarcheck":
		tarcheckUsage()
	case "upgrade":
		upgradeUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown help topic: %s\n\n", args[0])
		usage()
	}
}

func builddirCmd(args []string) {
	fs := flag.NewFlagSet("builddir", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = builddirUsage
	offline := fs.Bool("offline", true, "Forbid internet access while building (default)")
	online := fs.Bool("online", false, "Allow internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	forceBwrap := fs.Bool("bwrap", false, "Force bubblewrap isolation even when not offline")
	if err := fs.Parse(args); err != nil {
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

func builddirUsage() {
	fmt.Println("Usage: go-rua builddir [--online] [--offline] [--force] [--no-seccomp] [--bwrap] [dir]")
}

func shellcheckCmd(args []string) {
	fs := flag.NewFlagSet("shellcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = shellcheckUsage
	if err := fs.Parse(args); err != nil {
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

func shellcheckUsage() { fmt.Println("Usage: go-rua shellcheck [file|dir]") }

func namcapCmd(args []string) {
	fs := flag.NewFlagSet("namcap", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = namcapUsage
	if err := fs.Parse(args); err != nil {
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

func namcapUsage() { fmt.Println("Usage: go-rua namcap [file|dir]") }

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = installUsage
	offline := fs.Bool("offline", true, "Forbid internet access while building (default)")
	online := fs.Bool("online", false, "Allow internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	asdeps := fs.Bool("asdeps", false, "Install built packages as dependencies")
	planOnly := fs.Bool("plan", false, "Print build plan and exit")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	installBuilt := fs.Bool("install", false, "Install built artifacts after staging")
	if err := fs.Parse(args); err != nil {
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
		return installInstallFn(pkgs, p, install.Options{Offline: effOffline, Force: *force, InstallBuilt: *installBuilt, DisableSeccomp: *noSeccomp, AsDeps: *asdeps})
	})(); err != nil {
		fatalf("install failed: %v", err)
	}
}

func installUsage() {
	fmt.Println("Usage: go-rua install [--online] [--offline] [--force] [--install] [--asdeps] [--plan] [--install-repo-deps] [--no-seccomp] <pkgs...>")
	fmt.Println("Options:")
	fmt.Println("  --offline             Forbid internet access while building (default)")
	fmt.Println("  --online              Allow internet access while building")
	fmt.Println("  --force               Pass --force to makepkg")
	fmt.Println("  --install             Install built artifacts after staging")
	fmt.Println("  --asdeps              Install built packages as dependencies")
	fmt.Println("  --plan                Print build plan and exit")
	fmt.Println("  --install-repo-deps   Install missing repo deps with pacman")
	fmt.Println("  --no-seccomp          Disable seccomp denylist for build (debug)")
}

func searchCmd(args []string) {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = searchUsage
	if err := fs.Parse(args); err != nil {
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
	for _, p := range results {
		fmt.Printf("%s %s - %s\n", p.Name, p.Version, strings.TrimSpace(p.Description))
	}
}

func searchUsage() { fmt.Println("Usage: go-rua search <keywords...>") }

func infoCmd(args []string) {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = infoUsage
	jsonOut := fs.Bool("json", false, "Output JSON")
	if err := fs.Parse(args); err != nil {
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

func infoUsage() { fmt.Println("Usage: go-rua info [--json] <pkg1> [pkg2 ...]") }

func tarcheckCmd(args []string) {
	fs := flag.NewFlagSet("tarcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = tarcheckUsage
	if err := fs.Parse(args); err != nil {
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

func tarcheckUsage() { fmt.Println("Usage: go-rua tarcheck <archive>") }

func upgradeCmd(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = upgradeUsage
	printOnly := fs.Bool("printonly", false, "Print outdated packages and exit")
	apply := fs.Bool("apply", false, "Build and install upgrades after review")
	plan := fs.Bool("plan", false, "Print upgrade plan and exit")
	devel := fs.Bool("devel", false, "Also rebuild development VCS packages (-git, -hg, -bzr, -svn, -cvs, -darcs)")
	ignore := fs.String("ignore", "", "Comma-separated list of packages to ignore")
	offline := fs.Bool("offline", true, "Forbid internet access while building (default)")
	online := fs.Bool("online", false, "Allow internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	noSeccomp := fs.Bool("no-seccomp", false, "Disable seccomp denylist for build")
	if err := fs.Parse(args); err != nil {
		return
	}
	outdated, nonexistent, err := findOutdated(*devel, *ignore)
	if err != nil {
		fatalf("upgrade check failed: %v", err)
	}
	if len(outdated) == 0 && len(nonexistent) == 0 {
		os.Exit(7)
	}
	if *printOnly {
		for _, n := range outdated {
			fmt.Println(n)
		}
		for _, n := range nonexistent {
			fmt.Println(n)
		}
		return
	}
	// Planning is the default; --apply is required for build/install.
	if *plan || !*apply {
		// Detailed outdated table
		items, _, _ := listOutdatedDetailed(*devel, *ignore)
		if len(items) > 0 {
			fmt.Println(term.Bold("Outdated AUR packages:"))
			for _, it := range items {
				fmt.Printf("  %s  %s -> %s\n", it.Name, it.Local, it.Latest)
			}
		}
		pl, err := installPlanFn(outdated)
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
		if len(nonexistent) > 0 {
			fmt.Printf("  Note: %d installed packages not found in AUR: %s\n", len(nonexistent), strings.Join(nonexistent, ", "))
		}
		return
	}
	// apply/default: build and install in order
	pl, err := installPlanFn(outdated)
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
	for _, name := range pl.BuildOrder {
		fmt.Printf("\n==> Upgrading AUR pkg: %s\n", name)
		effOffline := *offline && !*online
		if err := installInstallFn([]string{name}, p, install.Options{Offline: effOffline, Force: *force, NonInteractive: false, InstallBuilt: true, DisableSeccomp: *noSeccomp}); err != nil {
			fatalf("upgrade failed for %s: %v", name, err)
		}
	}
}

func upgradeUsage() {
	fmt.Println("Usage: go-rua upgrade [--apply] [--plan] [--devel] [--ignore=<pkg1,pkg2>] [--online] [--offline] [--force] [--install-repo-deps] [--no-seccomp]")
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
