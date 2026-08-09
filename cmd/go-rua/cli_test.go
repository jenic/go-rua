package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"go-rua/internal/aur"
	installpkg "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
)

type rtCLIFunc func(*http.Request) (*http.Response, error)

func (f rtCLIFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mrespCLI(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func captureOut(f func()) (string, string) {
	oldOut, oldErr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	r1, w1, _ := os.Pipe()
	r2, w2, _ := os.Pipe()
	os.Stdout, os.Stderr = w1, w2
	f()
	w1.Close()
	w2.Close()
	b1, _ := io.ReadAll(r1)
	b2, _ := io.ReadAll(r2)
	return string(b1), string(b2)
}

func restoreCLISeams(t *testing.T) {
	t.Helper()
	oldAurInfo, oldAurSearchAND := aurInfoFn, aurSearchANDFn
	oldPlan, oldInstall := installPlanFn, installInstallFn
	oldSummary, oldFormatSummary := summarizeAURFn, formatSummaryFn
	oldSudo, oldRepoDeps := pacmanSudoFn, pacmanInstallRepoDepsFn
	oldForeign, oldVercmp, oldIgnored := getForeignPkgsFn, vercmpFn, getIgnoredPkgsFn
	oldTarcheck, oldShellcheck, oldNamcap := tarcheckFn, shellcheckFn, namcapFn
	oldPaths, oldPathsNoMakepkg := pathsInitFn, pathsInitNoMakepkgFn
	oldBuildDir := buildDirectoryCLIFn
	oldSourceAudit, oldFormatSourceAudit := sourceAuditDirFn, formatSourceAuditFn
	oldShellAudit, oldFormatShellAudit := shellAuditDirFn, formatShellAuditFn
	t.Cleanup(func() {
		aurInfoFn = oldAurInfo
		aurSearchANDFn = oldAurSearchAND
		installPlanFn = oldPlan
		installInstallFn = oldInstall
		summarizeAURFn = oldSummary
		formatSummaryFn = oldFormatSummary
		pacmanSudoFn = oldSudo
		pacmanInstallRepoDepsFn = oldRepoDeps
		getForeignPkgsFn = oldForeign
		vercmpFn = oldVercmp
		getIgnoredPkgsFn = oldIgnored
		tarcheckFn = oldTarcheck
		shellcheckFn = oldShellcheck
		namcapFn = oldNamcap
		pathsInitFn = oldPaths
		pathsInitNoMakepkgFn = oldPathsNoMakepkg
		buildDirectoryCLIFn = oldBuildDir
		sourceAuditDirFn = oldSourceAudit
		formatSourceAuditFn = oldFormatSourceAudit
		shellAuditDirFn = oldShellAudit
		formatShellAuditFn = oldFormatShellAudit
	})
}

func TestSearchCmd(t *testing.T) {
	restoreCLISeams(t)

	// Stub AUR search
	aurSearchANDFn = func(terms []string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", Version: "1", Description: "hello"}}, nil
	}
	out, _ := captureOut(func() { searchCmd([]string{"foo"}) })
	if !strings.Contains(out, "foo 1") || !strings.Contains(out, "hello") {
		t.Fatalf("unexpected search out: %q", out)
	}
}

func TestInfoCmdTextAndJSON(t *testing.T) {
	restoreCLISeams(t)

	aurInfoFn = func(names []string) ([]aur.Package, error) {
		return []aur.Package{{
			Name: "pkg", Version: "1", Description: "desc", URL: "u", Maintainer: "m",
			Depends: []string{"a"}, MakeDepends: []string{"b"}, CheckDepends: []string{"c"}, OptDepends: []string{"o"},
			Provides: []string{"p"}, Conflicts: []string{"x"}, OutOfDate: 123,
		}}, nil
	}
	out, _ := captureOut(func() { infoCmd([]string{"pkg"}) })
	if !strings.Contains(out, "pkg 1") || !strings.Contains(out, "depends:") || !strings.Contains(out, "conflicts:") {
		t.Fatalf("unexpected info out: %q", out)
	}
	// JSON flag path
	out2, _ := captureOut(func() { infoCmd([]string{"--json", "pkg"}) })
	var js []aur.Package
	if json.Unmarshal([]byte(out2), &js) != nil || len(js) != 1 || js[0].Name != "pkg" {
		t.Fatalf("unexpected JSON out: %q", out2)
	}
}

func TestUpgradeCmdPlanPrints(t *testing.T) {
	restoreCLISeams(t)

	// Stub findOutdated deps via seams used inside helpers
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names, RepoMissing: []string{"libx"}}, nil
	}
	pacmanSudoFn = func() string { return "sudo" }

	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order: foo") {
		t.Fatalf("unexpected upgrade plan out: %q", out)
	}
}

func TestUpgradeCmdPlanDoesNotInstall(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names}, nil
	}
	pacmanSudoFn = func() string { return "sudo" }
	installCalled := false
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		installCalled = true
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order: foo") {
		t.Fatalf("unexpected upgrade plan out: %q", out)
	}
	if installCalled {
		t.Fatal("upgrade --plan must not install")
	}
}

func TestUpgradeCmdDefaultsToInteractiveInstall(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names}, nil
	}
	pathsInitFn = func() paths.Paths {
		d := t.TempDir()
		return paths.Paths{ConfigDir: d, CacheBuildDir: d, DataCheckedTars: d}
	}
	var got installpkg.Options
	installInstallFn = func(_ []string, _ paths.Paths, opt installpkg.Options) error {
		got = opt
		return nil
	}

	captureOut(func() { upgradeCmd(nil) })
	if got.NonInteractive {
		t.Fatal("upgrade must keep review interactive")
	}
	if !got.InstallBuilt {
		t.Fatal("upgrade should install built artifacts by default")
	}
}

func TestUpgradeCmdDefaultReportsPackagesMissingFromAUR(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}, {Name: "ghost", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", Version: "2"}}, nil
	}
	vercmpFn = func(string, string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func([]string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: []string{"foo"}}, nil
	}
	pathsInitFn = func() paths.Paths { return paths.Paths{} }
	installed := false
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		installed = true
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd(nil) })
	if !strings.Contains(out, "installed packages not found in AUR: ghost") {
		t.Fatalf("upgrade output missing nonexistent package note: %q", out)
	}
	if !installed {
		t.Fatal("upgrade did not continue with the available outdated package")
	}
}

func TestUpgradeCmdDefaultStopsWhenOnlyPackagesMissingFromAUR(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "ghost", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) { return nil, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	workCalls := 0
	installPlanFn = func([]string) (installpkg.Plan, error) {
		workCalls++
		return installpkg.Plan{}, nil
	}
	pathsInitFn = func() paths.Paths {
		workCalls++
		return paths.Paths{}
	}
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		workCalls++
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd(nil) })
	if !strings.Contains(out, "installed packages not found in AUR: ghost") {
		t.Fatalf("upgrade output missing nonexistent package note: %q", out)
	}
	if workCalls != 0 {
		t.Fatalf("upgrade started %d plan, path, or install operations without outdated packages", workCalls)
	}
}

func TestInstallCmdInstallsByDefaultUnlessStageOnly(t *testing.T) {
	restoreCLISeams(t)

	pathsInitFn = func() paths.Paths {
		d := t.TempDir()
		return paths.Paths{ConfigDir: d, CacheBuildDir: d, DataCheckedTars: d}
	}
	aurInfoFn = func([]string) ([]aur.Package, error) { return nil, nil }
	summarizeAURFn = func([]string, []aur.Package) (installpkg.DepSummary, error) {
		return installpkg.DepSummary{}, nil
	}
	formatSummaryFn = func(installpkg.DepSummary) string { return "" }

	var got []installpkg.Options
	installInstallFn = func(_ []string, _ paths.Paths, opt installpkg.Options) error {
		got = append(got, opt)
		return nil
	}

	captureOut(func() { installCmd([]string{"pkg"}) })
	captureOut(func() { installCmd([]string{"--stage-only", "pkg"}) })

	if len(got) != 2 {
		t.Fatalf("install calls = %d, want 2", len(got))
	}
	if !got[0].InstallBuilt {
		t.Fatal("install should install built artifacts by default")
	}
	if got[1].InstallBuilt {
		t.Fatal("install --stage-only should not install built artifacts")
	}
}
