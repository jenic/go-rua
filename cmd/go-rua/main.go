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
	"go-rua/internal/shellutil"
)

var Version string

func usage() {
	fmt.Println("go-rua: AUR helper (Go), sandboxed by Landlock")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go-rua [command] [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  builddir [--offline] [--force] [dir]    Build a PKGBUILD directory in sandbox")
	fmt.Println("  shellcheck [file|dir]                   Run shellcheck for PKGBUILD (sandboxed)")
	fmt.Println("  namcap [file|dir]                       Run namcap for PKGBUILD (sandboxed)")
	fmt.Println("  install [--offline] [--force] [--install] [--plan] <pkgs..>  Clone AUR repos, review, build, stage, optional install")
	fmt.Println("  search <keywords...>                    Search AUR by name/desc")
	fmt.Println("  info <pkg1> [pkg2 ...]                  Show AUR package info")
	fmt.Println("  upgrade [--printonly|--apply]           Print or apply upgrades for AUR packages")
	fmt.Println("  version                                 Show version")
	fmt.Println()
}

func main() {
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
	offline := fs.Bool("offline", false, "Forbid internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
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

	p := paths.MustInit()
	if err := build.BuildDirectory(abs, p, *offline, *force); err != nil {
		fatalf("build failed: %v", err)
	}
}

func builddirUsage() { fmt.Println("Usage: go-rua builddir [--offline] [--force] [dir]") }

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

	p := paths.MustInitNoMakepkgChecks()
	if err := shellutil.Shellcheck(target, p); err != nil {
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
	p := paths.MustInitNoMakepkgChecks()
	if err := shellutil.Namcap(target, p); err != nil {
		fatalf("namcap failed: %v", err)
	}
}

func namcapUsage() { fmt.Println("Usage: go-rua namcap [file|dir]") }

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = installUsage
	offline := fs.Bool("offline", false, "Forbid internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	planOnly := fs.Bool("plan", false, "Print build plan and exit")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	installBuilt := fs.Bool("install", false, "Install built artifacts after staging")
	if err := fs.Parse(args); err != nil {
		return
	}
	pkgs := fs.Args()
	if len(pkgs) == 0 {
		fs.Usage()
		return
	}
	p := paths.MustInit()
	if err := buildDepsNote(); err != nil { /* ignore */
	}
	if *planOnly {
		infos, err := aur.Info(pkgs)
		if err != nil {
			fatalf("failed to fetch AUR info: %v", err)
		}
		sum, err := install.SummarizeForAUR(pkgs, infos)
		if err == nil {
			fmt.Print(install.FormatSummary(sum))
		}
		plan, err := install.BuildPlan(pkgs)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		fmt.Println("Plan:")
		if len(plan.BuildOrder) == 0 {
			fmt.Println("  (no AUR builds needed)")
		} else {
			fmt.Printf("  Build order: %s\n", strings.Join(plan.BuildOrder, ", "))
		}
		if len(plan.RepoMissing) > 0 {
			fmt.Printf("  Repo deps missing: %s\n", strings.Join(plan.RepoMissing, ", "))
			fmt.Printf("    Install: sudo pacman -S --needed %s\n", strings.Join(plan.RepoMissing, " "))
		} else {
			fmt.Println("  Repo deps missing: none")
		}
		if len(plan.Unknown) > 0 {
			fmt.Printf("  Unknown deps: %s\n", strings.Join(plan.Unknown, ", "))
		}
		return
	}
	// Print a pacman dependency summary before interactive steps
	if infos, err := aur.Info(pkgs); err == nil {
		if sum, err := install.SummarizeForAUR(pkgs, infos); err == nil {
			fmt.Print(install.FormatSummary(sum))
		}
	}
	// Optionally install missing repo deps
	if *installRepoDeps {
		plan, err := install.BuildPlan(pkgs)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		if len(plan.RepoMissing) > 0 {
			fmt.Printf("Installing missing repo deps: %s\n", strings.Join(plan.RepoMissing, ", "))
			if err := pacman.InstallRepoDeps(plan.RepoMissing); err != nil {
				fatalf("pacman install failed: %v", err)
			}
		}
	}
	if err := (func() error {
		return install.Install(pkgs, p, install.Options{Offline: *offline, Force: *force, InstallBuilt: *installBuilt})
	})(); err != nil {
		fatalf("install failed: %v", err)
	}
}

func installUsage() {
	fmt.Println("Usage: go-rua install [--offline] [--force] [--install] [--plan] [--install-repo-deps] <pkgs...>")
	fmt.Println("Options:")
	fmt.Println("  --offline             Forbid internet access while building")
	fmt.Println("  --force               Pass --force to makepkg")
	fmt.Println("  --install             Install built artifacts after staging")
	fmt.Println("  --plan                Print build plan and exit")
	fmt.Println("  --install-repo-deps   Install missing repo deps with pacman")
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
	results, err := aur.Search(fs.Args())
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
	if err := fs.Parse(args); err != nil {
		return
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return
	}
	info, err := aur.Info(fs.Args())
	if err != nil {
		fatalf("info failed: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		fatalf("encode failed: %v", err)
	}
}

func infoUsage() { fmt.Println("Usage: go-rua info <pkg1> [pkg2 ...]") }

func upgradeCmd(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = upgradeUsage
	printOnly := fs.Bool("printonly", false, "Print outdated packages and exit")
	apply := fs.Bool("apply", false, "Build and install outdated AUR packages")
	offline := fs.Bool("offline", false, "Forbid internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	installRepoDeps := fs.Bool("install-repo-deps", false, "Install missing repo deps with pacman")
	if err := fs.Parse(args); err != nil {
		return
	}
	outdated, err := findOutdated()
	if err != nil {
		fatalf("upgrade check failed: %v", err)
	}
	if len(outdated) == 0 {
		os.Exit(7)
	}
	if *printOnly && !*apply {
		for _, n := range outdated {
			fmt.Println(n)
		}
		return
	}
	// default without flags: print a plan
	if !*apply {
		plan, err := install.BuildPlan(outdated)
		if err != nil {
			fatalf("plan failed: %v", err)
		}
		fmt.Println("Plan:")
		if len(plan.BuildOrder) == 0 {
			fmt.Println("  (no AUR builds needed)")
		} else {
			fmt.Printf("  Build order: %s\n", strings.Join(plan.BuildOrder, ", "))
		}
		if len(plan.RepoMissing) > 0 {
			fmt.Printf("  Repo deps missing: %s\n", strings.Join(plan.RepoMissing, ", "))
			fmt.Printf("    Install: sudo pacman -S --needed %s\n", strings.Join(plan.RepoMissing, " "))
		} else {
			fmt.Println("  Repo deps missing: none")
		}
		if len(plan.Unknown) > 0 {
			fmt.Printf("  Unknown deps: %s\n", strings.Join(plan.Unknown, ", "))
		}
		return
	}
	// apply: build and install in order
	plan, err := install.BuildPlan(outdated)
	if err != nil {
		fatalf("plan failed: %v", err)
	}
	if *installRepoDeps && len(plan.RepoMissing) > 0 {
		fmt.Printf("Installing missing repo deps: %s\n", strings.Join(plan.RepoMissing, ", "))
		if err := pacman.InstallRepoDeps(plan.RepoMissing); err != nil {
			fatalf("pacman install failed: %v", err)
		}
	}
	p := paths.MustInit()
	for _, name := range plan.BuildOrder {
		fmt.Printf("\n==> Upgrading AUR pkg: %s\n", name)
		if err := install.Install([]string{name}, p, install.Options{Offline: *offline, Force: *force, NonInteractive: true, InstallBuilt: true}); err != nil {
			fatalf("upgrade failed for %s: %v", name, err)
		}
	}
}

func upgradeUsage() {
	fmt.Println("Usage: go-rua upgrade [--printonly|--apply] [--offline] [--force] [--install-repo-deps]")
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
func findOutdated() ([]string, error) {
	foreign, err := pacman.GetForeignPackages()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(foreign))
	for _, f := range foreign {
		names = append(names, f.Name)
	}
	if len(names) == 0 {
		return nil, nil
	}
	infos, err := aur.Info(names)
	if err != nil {
		return nil, err
	}
	byName := map[string]string{}
	for _, inf := range infos {
		byName[inf.Name] = inf.Version
	}
	var outdated []string
	for _, f := range foreign {
		latest := byName[f.Name]
		if latest == "" {
			continue
		}
		cmp, err := pacman.Vercmp(f.Version, latest)
		if err != nil {
			continue
		}
		if cmp < 0 {
			outdated = append(outdated, f.Name)
		}
	}
	return outdated, nil
}
