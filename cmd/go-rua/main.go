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

const version = "0.1.0"

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
	fmt.Println("  install [--offline] [--force] <pkgs..>  Clone AUR repos, review, build, stage artifacts")
	fmt.Println("  search <keywords...>                    Search AUR by name/desc")
	fmt.Println("  info <pkg1> [pkg2 ...]                  Show AUR package info")
	fmt.Println("  upgrade --printonly                     Print outdated foreign (AUR) packages")
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
		fmt.Println(version)
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
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func builddirCmd(args []string) {
	fs := flag.NewFlagSet("builddir", flag.ExitOnError)
	offline := fs.Bool("offline", false, "Forbid internet access while building")
	force := fs.Bool("force", false, "Pass --force to makepkg")
	_ = fs.Parse(args)

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

func shellcheckCmd(args []string) {
	fs := flag.NewFlagSet("shellcheck", flag.ExitOnError)
	_ = fs.Parse(args)
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

func namcapCmd(args []string) {
	fs := flag.NewFlagSet("namcap", flag.ExitOnError)
	_ = fs.Parse(args)
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

func installCmd(args []string) {
    fs := flag.NewFlagSet("install", flag.ExitOnError)
    offline := fs.Bool("offline", false, "Forbid internet access while building")
    force := fs.Bool("force", false, "Pass --force to makepkg")
    _ = fs.Parse(args)
    pkgs := fs.Args()
    if len(pkgs) == 0 {
        fatalf("install: need at least one package")
    }
    p := paths.MustInit()
    if err := buildDepsNote(); err != nil { /* ignore */
    }
    // Print a pacman dependency summary before interactive steps
    if infos, err := aur.Info(pkgs); err == nil {
        if sum, err := install.SummarizeForAUR(pkgs, infos); err == nil {
            fmt.Print(install.FormatSummary(sum))
        }
    }
    if err := (func() error {
        return install.Install(pkgs, p, install.Options{Offline: *offline, Force: *force})
    })(); err != nil {
        fatalf("install failed: %v", err)
    }
}

func searchCmd(args []string) {
	if len(args) == 0 {
		fatalf("search: need at least one keyword")
	}
	results, err := aur.Search(args)
	if err != nil {
		fatalf("search failed: %v", err)
	}
	for _, p := range results {
		fmt.Printf("%s %s - %s\n", p.Name, p.Version, strings.TrimSpace(p.Description))
	}
}

func infoCmd(args []string) {
	if len(args) == 0 {
		fatalf("info: need at least one package name")
	}
	info, err := aur.Info(args)
	if err != nil {
		fatalf("info failed: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		fatalf("encode failed: %v", err)
	}
}

func upgradeCmd(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	printOnly := fs.Bool("printonly", false, "Print outdated packages and exit")
	_ = fs.Parse(args)
	if !*printOnly {
		fatalf("only --printonly is implemented")
	}
	outdated, err := findOutdated()
	if err != nil {
		fatalf("upgrade check failed: %v", err)
	}
	if len(outdated) == 0 {
		// match rua behavior: exit code 7 if none
		os.Exit(7)
	}
	for _, n := range outdated {
		fmt.Println(n)
	}
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
