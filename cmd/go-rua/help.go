package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

const helpLineWidth = 88

type helpEntry struct {
	Label       string
	Description string
}

type helpSection struct {
	Title      string
	Paragraphs []string
	Entries    []helpEntry
}

type helpExample struct {
	Description string
	Command     string
}

type commandHelpSpec struct {
	Summary     string
	Usage       string
	Description []string
	Arguments   []helpEntry
	Sections    []helpSection
	Examples    []helpExample
	FlagValues  map[string]string
}

type renderedOption struct {
	name        string
	label       string
	description string
}

func setCommandUsage(fs *flag.FlagSet, spec commandHelpSpec) {
	fs.Usage = func() {
		printCommandHelp(fs.Output(), fs, spec)
	}
}

func printCommandHelp(w io.Writer, fs *flag.FlagSet, spec commandHelpSpec) {
	fmt.Fprintln(w, spec.Summary)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s\n", spec.Usage)

	if len(spec.Description) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Description:")
		for _, paragraph := range spec.Description {
			writeWrapped(w, "  ", paragraph)
		}
	}
	if len(spec.Arguments) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Arguments:")
		writeEntries(w, spec.Arguments)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	writeEntries(w, commandOptions(fs, spec.FlagValues))

	for _, section := range spec.Sections {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s:\n", section.Title)
		for _, paragraph := range section.Paragraphs {
			writeWrapped(w, "  ", paragraph)
		}
		writeEntries(w, section.Entries)
	}

	if len(spec.Examples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Examples:")
		for _, example := range spec.Examples {
			writeWrapped(w, "  ", example.Description)
			fmt.Fprintf(w, "    %s\n", example.Command)
		}
	}
}

func commandOptions(fs *flag.FlagSet, values map[string]string) []helpEntry {
	options := []renderedOption{
		{name: "color", label: "--color <when>", description: "Set color mode: always, never, or auto"},
		{name: "help", label: "-h, --help", description: "Show this help and exit"},
	}
	fs.VisitAll(func(f *flag.Flag) {
		label := "--" + f.Name
		if value := values[f.Name]; value != "" {
			label += " <" + value + ">"
		}
		description := strings.TrimSpace(f.Usage)
		if f.DefValue != "" && f.DefValue != "false" {
			description += fmt.Sprintf(" (default: %s)", f.DefValue)
		}
		options = append(options, renderedOption{name: f.Name, label: label, description: description})
	})
	sort.Slice(options, func(i, j int) bool { return options[i].name < options[j].name })

	entries := make([]helpEntry, 0, len(options))
	for _, option := range options {
		entries = append(entries, helpEntry{Label: option.label, Description: option.description})
	}
	return entries
}

func writeEntries(w io.Writer, entries []helpEntry) {
	if len(entries) == 0 {
		return
	}
	labelWidth := 0
	for _, entry := range entries {
		if len(entry.Label) > labelWidth && len(entry.Label) <= 28 {
			labelWidth = len(entry.Label)
		}
	}
	for _, entry := range entries {
		if len(entry.Label) > labelWidth {
			fmt.Fprintf(w, "  %s\n", entry.Label)
			writeWrapped(w, "      ", entry.Description)
			continue
		}
		first := fmt.Sprintf("  %-*s  ", labelWidth, entry.Label)
		continuation := strings.Repeat(" ", len(first))
		writeWrappedWithFirst(w, first, continuation, entry.Description)
	}
}

func writeWrapped(w io.Writer, indent, text string) {
	writeWrappedWithFirst(w, indent, indent, text)
}

func writeWrappedWithFirst(w io.Writer, firstPrefix, continuationPrefix, value string) {
	words := strings.Fields(value)
	if len(words) == 0 {
		fmt.Fprintln(w, firstPrefix)
		return
	}
	prefix := firstPrefix
	line := prefix
	for _, word := range words {
		separator := ""
		if len(line) > len(prefix) {
			separator = " "
		}
		if len(line)+len(separator)+len(word) > helpLineWidth && len(line) > len(prefix) {
			fmt.Fprintln(w, line)
			prefix = continuationPrefix
			line = prefix + word
			continue
		}
		line += separator + word
	}
	fmt.Fprintln(w, line)
}

func printGlobalHelp(w io.Writer) {
	fmt.Fprintln(w, "go-rua: AUR helper (Go), sandboxed by Landlock")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  go-rua [global options] <command> [options] [arguments]")
	fmt.Fprintln(w, "  go-rua help <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	writeEntries(w, []helpEntry{
		{Label: "builddir", Description: "Build a local PKGBUILD directory in a sandbox"},
		{Label: "shellcheck", Description: "Run shellcheck against a PKGBUILD in a sandbox"},
		{Label: "namcap", Description: "Run namcap against a PKGBUILD in a sandbox"},
		{Label: "install", Description: "Review, build, stage, and install AUR packages"},
		{Label: "search", Description: "Search AUR package names and descriptions"},
		{Label: "info", Description: "Show AUR package metadata"},
		{Label: "tarcheck", Description: "Interactively inspect a built package archive"},
		{Label: "upgrade", Description: "Review, build, and install available AUR upgrades"},
		{Label: "version", Description: "Print the go-rua version"},
	})
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global options:")
	writeEntries(w, []helpEntry{
		{Label: "--color <when>", Description: "Set color mode: always, never, or auto"},
		{Label: "-h, --help", Description: "Show global help"},
		{Label: "-v, --version", Description: "Print the go-rua version"},
	})
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	writeEntries(w, []helpEntry{
		{Label: "RUA_COLOR", Description: "Set color mode; overridden by --color"},
		{Label: "NO_COLOR", Description: "Disable color unless RUA_COLOR selects always"},
		{Label: "CLICOLOR_FORCE", Description: "Set to 1 to force color when RUA_COLOR is unset or auto"},
		{Label: "CLICOLOR", Description: "Set to 0 to disable color when RUA_COLOR is unset or auto"},
		{Label: "RUA_SUDO_COMMAND", Description: "Set the elevation command used for pacman (default: sudo)"},
		{Label: "XDG_CONFIG_HOME", Description: "Set the base directory for package review checkouts and configuration"},
		{Label: "XDG_CACHE_HOME", Description: "Set the base directory for package build workspaces"},
		{Label: "XDG_DATA_HOME", Description: "Set the base directory for reviewed package archives"},
	})
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'go-rua help <command>' for detailed command help.")
}

var builddirHelp = commandHelpSpec{
	Summary: "Build a local PKGBUILD directory in a sandbox.",
	Usage:   "go-rua builddir [options] [directory]",
	Description: []string{
		"Audit and build the PKGBUILD in a local directory with makepkg. Source URL and shell logic findings are printed as warnings, but do not block this command.",
		"Builds are offline by default. Source verification is prefetched before the main network-isolated build.",
	},
	Arguments: []helpEntry{
		{Label: "directory", Description: "Directory containing PKGBUILD (default: current directory)"},
	},
	Sections: []helpSection{
		{Title: "Output", Paragraphs: []string{"Package archives, sources, logs, and build output remain in the selected directory."}},
		{Title: "Environment", Entries: []helpEntry{
			{Label: "RUA_ALWAYS_BWRAP", Description: "Force bubblewrap isolation for the main build"},
			{Label: "RUA_NO_BWRAP", Description: "Disable bubblewrap; offline builds also require RUA_ALLOW_WEAK_OFFLINE=1"},
			{Label: "RUA_ALLOW_WEAK_OFFLINE", Description: "Accept Landlock-only isolation without guaranteed network isolation"},
			{Label: "MAKEPKG_CONF", Description: "Use an alternate makepkg configuration"},
		}},
	},
	Examples: []helpExample{
		{Description: "Build the current directory offline:", Command: "go-rua builddir"},
		{Description: "Build a specific directory with network access:", Command: "go-rua builddir --online /path/to/package"},
		{Description: "Force bubblewrap even for an online build:", Command: "go-rua builddir --online --bwrap /path/to/package"},
	},
}

var shellcheckHelp = commandHelpSpec{
	Summary: "Run shellcheck against a PKGBUILD in a sandbox.",
	Usage:   "go-rua shellcheck [file|directory]",
	Description: []string{
		"Wrap the PKGBUILD with definitions for common makepkg variables, then run shellcheck --norc in a read-only sandbox.",
	},
	Arguments: []helpEntry{
		{Label: "file|directory", Description: "PKGBUILD file, a directory containing PKGBUILD, or standard input when omitted"},
	},
	Sections: []helpSection{
		{Title: "Requirements", Paragraphs: []string{"The shellcheck executable must be available on PATH."}},
	},
	Examples: []helpExample{
		{Description: "Check PKGBUILD in the current directory:", Command: "go-rua shellcheck ."},
		{Description: "Check a specific file:", Command: "go-rua shellcheck /path/to/PKGBUILD"},
		{Description: "Check content from standard input:", Command: "cat PKGBUILD | go-rua shellcheck"},
	},
}

var namcapHelp = commandHelpSpec{
	Summary: "Run namcap against a PKGBUILD in a sandbox.",
	Usage:   "go-rua namcap [file|directory]",
	Description: []string{
		"Run namcap with read-only access to the selected PKGBUILD directory and system tools.",
	},
	Arguments: []helpEntry{
		{Label: "file|directory", Description: "PKGBUILD file or directory containing PKGBUILD (default: current directory)"},
	},
	Sections: []helpSection{
		{Title: "Requirements", Paragraphs: []string{"The namcap executable must be available on PATH."}},
	},
	Examples: []helpExample{
		{Description: "Check PKGBUILD in the current directory:", Command: "go-rua namcap"},
		{Description: "Check another package directory:", Command: "go-rua namcap /path/to/package"},
	},
}

var installHelp = commandHelpSpec{
	Summary: "Review, build, stage, and install AUR packages.",
	Usage:   "go-rua install [options] <package>...",
	Description: []string{
		"Resolve the requested AUR packages and their transitive AUR dependencies, review each package repository, build in dependency order, inspect the archives, stage them, and install them with pacman -U.",
		"Installation is the default and performs a privileged package-manager operation. Use --plan to inspect dependency resolution only or --stage-only to stop before pacman -U.",
	},
	Arguments: []helpEntry{
		{Label: "package...", Description: "One or more AUR package names"},
	},
	Sections: []helpSection{
		{Title: "Workflow", Entries: []helpEntry{
			{Label: "Review", Description: "Fetch or update a persistent AUR Git checkout and audit source URLs and shell logic"},
			{Label: "Build", Description: "Copy approved files into a sandboxed build workspace and run makepkg"},
			{Label: "Inspect", Description: "Interactively inspect each produced package archive"},
			{Label: "Finish", Description: "Stage reviewed archives, then install them unless --stage-only was supplied"},
		}},
		{Title: "Review controls", Entries: []helpEntry{
			{Label: "S / N", Description: "Run shellcheck or namcap"},
			{Label: "T", Description: "Open a writable sandboxed shell in the review checkout"},
			{Label: "D / M", Description: "View differences or merge fetched upstream changes"},
			{Label: "U / H", Description: "Acknowledge source URL or shell logic warnings when required"},
			{Label: "O", Description: "Approve the reviewed package and continue"},
		}},
		{Title: "Paths", Entries: []helpEntry{
			{Label: "Review", Description: "$XDG_CONFIG_HOME/rua/pkg/<pkgbase> (default: ~/.config/rua/pkg)"},
			{Label: "Build", Description: "$XDG_CACHE_HOME/rua/build/<pkgbase> (default: ~/.cache/rua/build)"},
			{Label: "Staged", Description: "$XDG_DATA_HOME/rua/checked_tars/<pkgbase> (default: ~/.local/share/rua/checked_tars)"},
		}},
		{Title: "Environment", Entries: []helpEntry{
			{Label: "RUA_SUDO_COMMAND", Description: "Set the elevation command used for pacman (default: sudo)"},
			{Label: "RUA_NO_BWRAP", Description: "Disable bubblewrap; offline builds also require RUA_ALLOW_WEAK_OFFLINE=1"},
			{Label: "RUA_ALLOW_WEAK_OFFLINE", Description: "Accept Landlock-only fallback without guaranteed network isolation"},
		}},
		{Title: "Safety", Paragraphs: []string{"--stage-only prevents pacman -U, but combining it with --install-repo-deps can still invoke privileged pacman -S."}},
	},
	Examples: []helpExample{
		{Description: "Inspect the dependency and build plan without building or installing packages:", Command: "go-rua install --plan yay"},
		{Description: "Review, build, and install a package:", Command: "go-rua install yay"},
		{Description: "Build and stage without installing:", Command: "go-rua install --stage-only yay"},
		{Description: "Install missing repository dependencies automatically:", Command: "go-rua install --install-repo-deps yay"},
	},
}

var searchHelp = commandHelpSpec{
	Summary: "Search AUR package names and descriptions.",
	Usage:   "go-rua search <keyword>...",
	Description: []string{
		"Query the AUR RPC API and print matching package names, versions, and descriptions. Every supplied keyword must match.",
	},
	Arguments: []helpEntry{
		{Label: "keyword...", Description: "One or more case-insensitive search terms combined with AND semantics"},
	},
	Examples: []helpExample{
		{Description: "Search for packages matching both terms:", Command: "go-rua search terminal emulator"},
	},
}

var infoHelp = commandHelpSpec{
	Summary: "Show metadata for AUR packages.",
	Usage:   "go-rua info [options] <package>...",
	Description: []string{
		"Query the AUR RPC API for package metadata, dependencies, provides, conflicts, popularity, and maintenance status.",
	},
	Arguments: []helpEntry{
		{Label: "package...", Description: "One or more exact AUR package names"},
	},
	Examples: []helpExample{
		{Description: "Show human-readable metadata:", Command: "go-rua info yay paru"},
		{Description: "Emit the raw result array as formatted JSON:", Command: "go-rua info --json yay"},
	},
}

var tarcheckHelp = commandHelpSpec{
	Summary: "Interactively inspect a built package archive.",
	Usage:   "go-rua tarcheck <archive>",
	Description: []string{
		"List and inspect package contents before installation. Archive access and the optional review shell are sandboxed read-only.",
	},
	Arguments: []helpEntry{
		{Label: "archive", Description: "Existing Arch package archive, such as a .pkg.tar.zst file"},
	},
	Sections: []helpSection{
		{Title: "Review controls", Entries: []helpEntry{
			{Label: "E / L", Description: "List executable files or all packaged files"},
			{Label: "F", Description: "List packaged paths not currently present on the filesystem"},
			{Label: "S", Description: "List SUID or SGID files when present"},
			{Label: "I", Description: "Show .INSTALL content when present"},
			{Label: "T", Description: "Open a sandboxed shell with read-only archive-directory access"},
			{Label: "O / Q", Description: "Approve and continue, or quit with status 1"},
		}},
	},
	Examples: []helpExample{
		{Description: "Inspect a built package archive:", Command: "go-rua tarcheck ./pkgname-1.0-1-x86_64.pkg.tar.zst"},
	},
}

var upgradeHelp = commandHelpSpec{
	Summary: "Review, build, and install available AUR upgrades.",
	Usage:   "go-rua upgrade [options]",
	Description: []string{
		"Compare installed foreign packages with AUR versions, compute dependency order, review each outdated package, and install the resulting archives.",
		"Applying upgrades is the default and performs privileged package-manager operations. Use --plan or --printonly to inspect available work without building or installing packages.",
	},
	Sections: []helpSection{
		{Title: "Modes", Entries: []helpEntry{
			{Label: "Default", Description: "Review, build, stage, and install every selected upgrade"},
			{Label: "--plan", Description: "Show version changes, build order, repository dependencies, and unknown dependencies"},
			{Label: "--printonly", Description: "Print package names only; takes precedence over --plan"},
		}},
		{Title: "Review", Paragraphs: []string{"Each package uses the same interactive review, audit acknowledgement, archive inspection, and persistent checkout workflow as go-rua install."}},
		{Title: "Environment", Entries: []helpEntry{
			{Label: "RUA_SUDO_COMMAND", Description: "Set the elevation command used for pacman (default: sudo)"},
			{Label: "RUA_NO_BWRAP", Description: "Disable bubblewrap; offline builds also require RUA_ALLOW_WEAK_OFFLINE=1"},
			{Label: "RUA_ALLOW_WEAK_OFFLINE", Description: "Accept Landlock-only fallback without guaranteed network isolation"},
		}},
		{Title: "Exit status", Paragraphs: []string{"Returns status 7 when no outdated or missing AUR packages are found."}},
	},
	Examples: []helpExample{
		{Description: "Inspect the upgrade plan without making changes:", Command: "go-rua upgrade --plan"},
		{Description: "Review, build, and install available upgrades:", Command: "go-rua upgrade"},
		{Description: "Also install missing repository dependencies:", Command: "go-rua upgrade --install-repo-deps"},
		{Description: "Include development VCS packages but ignore selected packages:", Command: "go-rua upgrade --devel --ignore=foo,bar"},
	},
	FlagValues: map[string]string{"ignore": "packages"},
}

var versionHelp = commandHelpSpec{
	Summary: "Print the go-rua version.",
	Usage:   "go-rua version",
	Description: []string{
		"Print the version embedded in the go-rua binary and exit.",
	},
	Examples: []helpExample{
		{Description: "Print the current version:", Command: "go-rua version"},
	},
}
