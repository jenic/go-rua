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
	// Stub AUR info and plan
	oldInfo, oldPlan := aurInfoFn, installPlanFn
	oldSum, oldFmt := summarizeAURFn, formatSummaryFn
	defer func() {
		aurInfoFn = oldInfo
		installPlanFn = oldPlan
		summarizeAURFn = oldSum
		formatSummaryFn = oldFmt
	}()
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
	// Prepare getForeign and AUR info for one outdated and one nonexistent
	oldGF, oldAI, oldVC, oldGI := getForeignPkgsFn, aurInfoFn, vercmpFn, getIgnoredPkgsFn
	defer func() { getForeignPkgsFn = oldGF; aurInfoFn = oldAI; vercmpFn = oldVC; getIgnoredPkgsFn = oldGI }()
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}, {Name: "ghost", Version: "1"}}, nil
	}
	// use HTTP client to return info for only foo
	aur.SetHTTPClientForTests(&http.Client{Transport: rtCLIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			return mrespCLI2(200, `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"foo","Version":"2"}]}`), nil
		}
		return mrespCLI2(404, ""), nil
	})})
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

func TestInstallCmdInstallRepoDeps(t *testing.T) {
	// Stub plan with repo missing
	oldPlan, oldPac, oldInfo, oldSum, oldFmt, oldInstall := installPlanFn, pacmanInstallRepoDepsFn, aurInfoFn, summarizeAURFn, formatSummaryFn, installInstallFn
	defer func() {
		installPlanFn = oldPlan
		pacmanInstallRepoDepsFn = oldPac
		aurInfoFn = oldInfo
		summarizeAURFn = oldSum
		formatSummaryFn = oldFmt
		installInstallFn = oldInstall
	}()
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{RepoMissing: []string{"libx"}}, nil
	}
	pacmanInstallRepoDepsFn = func(names []string) error { return nil }
	aurInfoFn = func(names []string) ([]aur.Package, error) { return nil, nil }
	summarizeAURFn = func(pkgs []string, infos []aur.Package) (installpkg.DepSummary, error) {
		return installpkg.DepSummary{}, nil
	}
	formatSummaryFn = func(installpkg.DepSummary) string { return "" }
	// isolate XDG dirs to avoid permission issues even if install runs
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	// No-op for install to avoid side effects
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error { return nil }
	out, _ := captureOut(func() { installCmd([]string{"--install-repo-deps", "x"}) })
	if !strings.Contains(out, "Installing missing repo deps:") {
		t.Fatalf("expected repo deps msg")
	}
}
