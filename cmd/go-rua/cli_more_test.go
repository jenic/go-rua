package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
	installpkg "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/sourceaudit"
)

type rtCLIFunc2 func(*http.Request) (*http.Response, error)

func (f rtCLIFunc2) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mrespCLI2(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestHelpCmdTopics(t *testing.T) {
	topics := []string{"builddir", "shellcheck", "namcap", "install", "search", "info", "tarcheck", "upgrade", "unknown"}
	for _, tp := range topics {
		helpCmd([]string{tp})
	}
}

func TestTarcheckCmd(t *testing.T) {
	restoreCLISeams(t)

	// Make a temp file to pass arg check
	f, _ := os.CreateTemp("", "pkg-*.pkg.tar.zst")
	f.Close()
	defer os.Remove(f.Name())
	// stub tarcheckFn
	old := tarcheckFn
	tarcheckFn = func(string) error { return nil }
	defer func() { tarcheckFn = old }()
	_, errOut := captureOut(func() { tarcheckCmd([]string{f.Name()}) })
	if !strings.Contains(errOut, "Finished checking package:") {
		t.Fatalf("expected finished message, got %q", errOut)
	}
}

func TestInstallCmdPlanOnly(t *testing.T) {
	restoreCLISeams(t)

	// Stub AUR info and plan
	oldInfo, oldPlan := aurInfoFn, installPlanFn
	oldSum, oldFmt := summarizeAURFn, formatSummaryFn
	oldPaths := pathsInitFn
	defer func() {
		aurInfoFn = oldInfo
		installPlanFn = oldPlan
		summarizeAURFn = oldSum
		formatSummaryFn = oldFmt
		pathsInitFn = oldPaths
	}()
	pathsInitFn = func() paths.Paths {
		dir := t.TempDir()
		return paths.Paths{ConfigDir: dir, CacheBuildDir: dir, DataCheckedTars: dir}
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "x"}}, nil }
	summarizeAURFn = func(pkgs []string, infos []aur.Package) (installpkg.DepSummary, error) {
		return installpkg.DepSummary{Targets: pkgs}, nil
	}
	formatSummaryFn = func(s installpkg.DepSummary) string { return "Summary:\n" }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: []string{"x"}, RepoMissing: []string{"liby"}, Unknown: []string{"virt"}}, nil
	}
	out, _ := captureOut(func() { installCmd([]string{"--plan", "x"}) })
	if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order:") {
		t.Fatalf("unexpected install plan out: %q", out)
	}
}

func TestUpgradeCmdPrintOnlyFlag(t *testing.T) {
	restoreCLISeams(t)

	// Prepare getForeign and AUR info for one outdated and one nonexistent
	oldGF, oldAI, oldVC, oldGI := getForeignPkgsFn, aurInfoFn, vercmpFn, getIgnoredPkgsFn
	defer func() { getForeignPkgsFn = oldGF; aurInfoFn = oldAI; vercmpFn = oldVC; getIgnoredPkgsFn = oldGI }()
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}, {Name: "ghost", Version: "1"}}, nil
	}
	// use HTTP client to return info for only foo
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtCLIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			return mrespCLI2(200, `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"foo","Version":"2"}]}`), nil
		}
		return mrespCLI2(404, ""), nil
	})}))
	aurInfoFn = aur.Info
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }

	out, _ := captureOut(func() { upgradeCmd([]string{"--printonly"}) })
	if !(strings.Contains(out, "foo") && strings.Contains(out, "ghost")) {
		t.Fatalf("unexpected printonly out: %q", out)
	}
}

func TestBuilddirShellcheckNamcapWrappers(t *testing.T) {
	restoreCLISeams(t)

	oldPaths, oldPathsNoMakepkg := pathsInitFn, pathsInitNoMakepkgFn
	defer func() {
		pathsInitFn = oldPaths
		pathsInitNoMakepkgFn = oldPathsNoMakepkg
	}()
	pathsInitFn = func() paths.Paths {
		dir := t.TempDir()
		return paths.Paths{ConfigDir: dir, CacheBuildDir: dir, DataCheckedTars: dir}
	}
	pathsInitNoMakepkgFn = pathsInitFn

	// Builddir
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(""), 0o644)
	called := false
	oldBD := buildDirectoryCLIFn
	buildDirectoryCLIFn = func(abs string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		called = strings.HasSuffix(abs, dir)
		return nil
	}
	defer func() { buildDirectoryCLIFn = oldBD }()
	builddirCmd([]string{dir})
	if !called {
		t.Fatalf("builddir not invoked")
	}

	// Shellcheck resolves directory -> PKGBUILD
	oldSC := shellcheckFn
	defer func() { shellcheckFn = oldSC }()
	seenTarget := ""
	shellcheckFn = func(target string, _ paths.Paths) error { seenTarget = target; return nil }
	shellcheckCmd([]string{dir})
	if !strings.HasSuffix(seenTarget, filepath.Join(dir, "PKGBUILD")) {
		t.Fatalf("shellcheck wrong target: %s", seenTarget)
	}

	// Namcap
	oldNC := namcapFn
	defer func() { namcapFn = oldNC }()
	seenTarget = ""
	namcapFn = func(target string, _ paths.Paths) error { seenTarget = target; return nil }
	namcapCmd([]string{dir})
	if !strings.HasSuffix(seenTarget, dir) {
		t.Fatalf("namcap wrong target: %s", seenTarget)
	}
}

func TestBuilddirPrintsSourceAuditWarnings(t *testing.T) {
	restoreCLISeams(t)

	oldPaths := pathsInitFn
	oldBD := buildDirectoryCLIFn
	oldAudit := sourceAuditDirFn
	oldFormat := formatSourceAuditFn
	defer func() {
		pathsInitFn = oldPaths
		buildDirectoryCLIFn = oldBD
		sourceAuditDirFn = oldAudit
		formatSourceAuditFn = oldFormat
	}()
	pathsInitFn = func() paths.Paths {
		dir := t.TempDir()
		return paths.Paths{ConfigDir: dir, CacheBuildDir: dir, DataCheckedTars: dir}
	}
	buildDirectoryCLIFn = func(string, paths.Paths, bool, bool, bool) error { return nil }
	sourceAuditDirFn = func(string) (sourceaudit.Report, error) {
		return sourceaudit.Report{Incomplete: []string{"source contains shell expansion"}}, nil
	}
	formatSourceAuditFn = func(sourceaudit.Report) string { return "Source URL warnings:\n" }

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut := captureOut(func() { builddirCmd([]string{dir}) })
	if !strings.Contains(errOut, "Source URL warnings:") {
		t.Fatalf("expected source audit warning, got %q", errOut)
	}
}

func TestInstallCmdInstallRepoDeps(t *testing.T) {
	restoreCLISeams(t)

	// Stub plan with repo missing
	oldPlan, oldPac, oldInfo, oldSum, oldFmt, oldInstall := installPlanFn, pacmanInstallRepoDepsFn, aurInfoFn, summarizeAURFn, formatSummaryFn, installInstallFn
	oldPaths := pathsInitFn
	defer func() {
		installPlanFn = oldPlan
		pacmanInstallRepoDepsFn = oldPac
		aurInfoFn = oldInfo
		summarizeAURFn = oldSum
		formatSummaryFn = oldFmt
		installInstallFn = oldInstall
		pathsInitFn = oldPaths
	}()
	pathsInitFn = func() paths.Paths {
		dir := t.TempDir()
		return paths.Paths{ConfigDir: dir, CacheBuildDir: dir, DataCheckedTars: dir}
	}
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{RepoMissing: []string{"libx"}}, nil
	}
	pacmanInstallRepoDepsFn = func(names []string) error { return nil }
	aurInfoFn = func(names []string) ([]aur.Package, error) { return nil, nil }
	summarizeAURFn = func(pkgs []string, infos []aur.Package) (installpkg.DepSummary, error) {
		return installpkg.DepSummary{}, nil
	}
	formatSummaryFn = func(installpkg.DepSummary) string { return "" }
	// No-op for install to avoid side effects
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error { return nil }
	out, _ := captureOut(func() { installCmd([]string{"--install-repo-deps", "x"}) })
	if !strings.Contains(out, "Installing missing repo deps:") {
		t.Fatalf("expected repo deps msg")
	}
}
