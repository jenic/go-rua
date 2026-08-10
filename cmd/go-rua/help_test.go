package main

import (
	"strings"
	"testing"

	"go-rua/internal/aur"
	installpkg "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
)

func TestCommandHelpIsCompleteAndConsistent(t *testing.T) {
	tests := []struct {
		topic         string
		run           func([]string)
		wantArguments bool
		wantFlags     []string
		wantText      []string
	}{
		{topic: "builddir", run: builddirCmd, wantArguments: true, wantFlags: []string{"--bwrap", "--force", "--no-seccomp", "--offline", "--online"}, wantText: []string{"Output:", "Environment:"}},
		{topic: "shellcheck", run: shellcheckCmd, wantArguments: true, wantText: []string{"Requirements:", "standard input"}},
		{topic: "namcap", run: namcapCmd, wantArguments: true, wantText: []string{"Requirements:", "current directory"}},
		{topic: "install", run: installCmd, wantArguments: true, wantFlags: []string{"--asdeps", "--force", "--install-repo-deps", "--no-seccomp", "--offline", "--online", "--plan", "--stage-only"}, wantText: []string{"Workflow:", "Review controls:", "Paths:", "Safety:", "pacman -U"}},
		{topic: "search", run: searchCmd, wantArguments: true, wantText: []string{"AND semantics"}},
		{topic: "info", run: infoCmd, wantArguments: true, wantFlags: []string{"--json"}, wantText: []string{"formatted JSON"}},
		{topic: "tarcheck", run: tarcheckCmd, wantArguments: true, wantText: []string{"Review controls:", "O / Q"}},
		{topic: "upgrade", run: upgradeCmd, wantFlags: []string{"--devel", "--force", "--ignore <packages>", "--install-repo-deps", "--no-seccomp", "--no-upstream-check", "--offline", "--online", "--plan", "--printonly", "--upstream", "--validate-all-arches"}, wantText: []string{"Modes:", "Upstream overrides:", ".sha256.asc", "Exit status:", "status 7", "privileged", "ephemeral"}},
		{topic: "upstream", run: upstreamCmd, wantArguments: true, wantFlags: []string{"--export-evidence <directory>", "--gc-evidence", "--json"}, wantText: []string{"Configuration:", "Evidence:", "github_upstream.json", "atomically"}},
		{topic: "version", run: versionCmd},
	}

	for _, tt := range tests {
		t.Run(tt.topic, func(t *testing.T) {
			longOut, longErr := captureOut(func() { tt.run([]string{"--help"}) })
			shortOut, shortErr := captureOut(func() { tt.run([]string{"-h"}) })
			topicOut, topicErr := captureOut(func() { helpCmd([]string{tt.topic}) })

			if longErr != "" || shortErr != "" || topicErr != "" {
				t.Fatalf("help wrote stderr: long=%q short=%q topic=%q", longErr, shortErr, topicErr)
			}
			if longOut != shortOut || longOut != topicOut {
				t.Fatalf("help paths differ\n--help:\n%s\n-h:\n%s\nhelp topic:\n%s", longOut, shortOut, topicOut)
			}

			for _, want := range []string{"Usage:", "Description:", "Options:", "--color <when>", "-h, --help", "Examples:"} {
				if !strings.Contains(longOut, want) {
					t.Errorf("help missing %q\n%s", want, longOut)
				}
			}
			if tt.wantArguments && !strings.Contains(longOut, "Arguments:") {
				t.Errorf("help missing Arguments section\n%s", longOut)
			}
			for _, want := range append(tt.wantFlags, tt.wantText...) {
				if !strings.Contains(longOut, want) {
					t.Errorf("help missing %q\n%s", want, longOut)
				}
			}
			for _, line := range strings.Split(longOut, "\n") {
				if len(line) > helpLineWidth {
					t.Errorf("help line is %d columns, want <= %d: %q", len(line), helpLineWidth, line)
				}
			}
		})
	}
}

func TestCommandHelpDoesNotStartCommandWork(t *testing.T) {
	restoreCLISeams(t)

	calls := 0
	pathsInitFn = func() paths.Paths { calls++; return paths.Paths{} }
	pathsInitNoMakepkgFn = func() paths.Paths { calls++; return paths.Paths{} }
	aurInfoFn = func([]string) ([]aur.Package, error) { calls++; return nil, nil }
	aurSearchANDFn = func([]string) ([]aur.Package, error) { calls++; return nil, nil }
	installPlanFn = func([]string) (installpkg.Plan, error) { calls++; return installpkg.Plan{}, nil }
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error { calls++; return nil }
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) { calls++; return nil, nil }
	tarcheckFn = func(string) error { calls++; return nil }
	buildDirectoryCLIFn = func(string, paths.Paths, bool, bool, bool) error { calls++; return nil }

	commands := []func([]string){builddirCmd, shellcheckCmd, namcapCmd, installCmd, searchCmd, infoCmd, tarcheckCmd, upgradeCmd, upstreamCmd, versionCmd}
	for _, command := range commands {
		captureOut(func() { command([]string{"--help"}) })
	}
	if calls != 0 {
		t.Fatalf("help started %d command operations", calls)
	}
}

func TestGlobalHelpListsPublicInterface(t *testing.T) {
	out, errOut := captureOut(usage)
	if errOut != "" {
		t.Fatalf("global help wrote stderr: %q", errOut)
	}
	for _, want := range []string{
		"go-rua: AUR helper",
		"go-rua help <command>",
		"Commands:",
		"install",
		"upgrade",
		"upstream",
		"version",
		"Global options:",
		"--color <when>",
		"-v, --version",
		"Environment:",
		"RUA_SUDO_COMMAND",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("global help missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "sandbox-exec") {
		t.Errorf("global help exposed internal sandbox-exec command\n%s", out)
	}
}
